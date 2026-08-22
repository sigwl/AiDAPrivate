#pragma once
#include <ntifs.h>
#include <intrin.h>

#include <function/Struct.h>
#include <function/Functions.h>
#include <function/CoreSecurity.h>
#include <function/DebugEvents.h>
#include <function/MalwareSafe.h>

namespace ioctl_codes {
    constexpr ULONG kFunctionBase = 0x800;

    __forceinline ULONG make(ULONG offset) {
        return 0x00220000u | ((kFunctionBase + offset) << 2);
    }

    __forceinline ULONG DB()  { return make(0); }
    __forceinline ULONG PRW() { return make(1); }
    __forceinline ULONG BA()  { return make(2); }
    __forceinline ULONG RC()  { return make(4); }
    __forceinline ULONG CR()  { return make(5); }
    __forceinline ULONG AM()  { return make(6); }
    __forceinline ULONG FM()  { return make(7); }


    __forceinline ULONG TCTX()  { return make(9); }
    __forceinline ULONG TENUM() { return make(10); }
    __forceinline ULONG TSR()   { return make(11); }
    __forceinline ULONG QM()    { return make(12); }
    __forceinline ULONG PM()    { return make(13); }
    __forceinline ULONG ER()    { return make(14); }
    __forceinline ULONG RPEB()  { return make(15); }
    __forceinline ULONG SDF()   { return make(16); }
    __forceinline ULONG MEX()   { return make(17); }
    __forceinline ULONG V2P()   { return make(18); }


    __forceinline ULONG NCON() { return make(19); }
    __forceinline ULONG NCAP() { return make(20); }
    __forceinline ULONG NCPG() { return make(21); }
    __forceinline ULONG NDNS() { return make(22); }
    __forceinline ULONG NFLT() { return make(23); }
    __forceinline ULONG NSTS() { return make(24); }


    __forceinline ULONG EWFP() { return make(25); }
    __forceinline ULONG GSKT() { return make(26); }
    __forceinline ULONG SNBF() { return make(27); }
    __forceinline ULONG DTCP() { return make(28); }


    __forceinline ULONG PINJ() { return make(29); }
    __forceinline ULONG PMOD() { return make(30); }
    __forceinline ULONG PRED() { return make(31); }
    __forceinline ULONG STRM() { return make(32); }
    __forceinline ULONG DPIN() { return make(33); }
    __forceinline ULONG IHLD() { return make(34); }
    __forceinline ULONG CKIL() { return make(35); }
    __forceinline ULONG DNSS() { return make(36); }
    __forceinline ULONG BWMN() { return make(37); }
    __forceinline ULONG NIFS() { return make(38); }
    __forceinline ULONG PCEX() { return make(39); }
    __forceinline ULONG NFPR() { return make(40); }
    __forceinline ULONG EVTS() { return make(54); }

    __forceinline ULONG PSBX() { return make(55); }
    __forceinline ULONG USBX() { return make(56); }
    __forceinline ULONG NLOG() { return make(57); }
    __forceinline ULONG NPKT() { return make(58); }
    __forceinline ULONG SSDT() { return make(59); }
    __forceinline ULONG TQIF() { return make(60); }
    __forceinline ULONG TTERM(){ return make(61); }
    __forceinline ULONG HCLS() { return make(62); }
}

namespace dispatcher {

    __forceinline UINT64 requestor_pid_to_u64(PIRP irp) {
        return irp ? static_cast<UINT64>(IoGetRequestorProcessId(irp)) : 0;
    }

    __forceinline UINT64 remote_call_diag_mix(UINT64 value, UINT64 input) {
        value ^= input + 0x9E3779B97F4A7C15ULL + (value << 6) + (value >> 2);
        return value;
    }

    __forceinline UINT64 remote_call_diag_fingerprint(p_remote_call request) {
        if (!request)
            return 0;
        UINT64 value = 0xA1DA778100000001ULL;
        value = remote_call_diag_mix(value, request->dtb);
        value = remote_call_diag_mix(value, request->target_function);
        value = remote_call_diag_mix(value, request->shellcode_address);
        value = remote_call_diag_mix(value, request->spoof_return);
        value = remote_call_diag_mix(value, request->arg1);
        value = remote_call_diag_mix(value, request->arg2);
        value = remote_call_diag_mix(value, request->arg3);
        value = remote_call_diag_mix(value, request->arg4);
        value = remote_call_diag_mix(value, request->original_rip);
        return value;
    }

    __forceinline UINT64 call_result_diag_fingerprint(p_call_result request) {
        if (!request)
            return 0;
        UINT64 value = 0xA1DA778200000001ULL;
        value = remote_call_diag_mix(value, request->dtb);
        value = remote_call_diag_mix(value, request->result_address);
        value = remote_call_diag_mix(value, request->result);
        value = remote_call_diag_mix(value, request->completed);
        return value;
    }

    __forceinline NTSTATUS Pilot(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

        if (malware_safe::any_sandboxed()) {
            HANDLE caller_pid = PsGetCurrentProcessId();
            ULONG flags = 0;
            if (malware_safe::is_sandboxed_pid(caller_pid, &flags) &&
                (flags & malware_safe::FLAG_BLOCK_KERNEL_HANDLE)) {
                malware_safe::record_denial(caller_pid);
                WW_MALSAFE_LOG_INFO("DENY kernel_device_open pid=%lu flags=0x%08X status=0x%08X",
                    (ULONG)(ULONG_PTR)caller_pid, flags, STATUS_ACCESS_DENIED);
                irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                irp->IoStatus.Information = 0;
                _IofCompleteRequest(irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }
        }

        if (stack && stack->MajorFunction == IRP_MJ_CREATE) {
            caller_validation::register_client();
        } else if (stack && stack->MajorFunction == IRP_MJ_CLOSE) {
            if (caller_validation::is_registered_client(PsGetCurrentProcessId())) {
                caller_validation::unregister_client();
            }
        }

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    __forceinline NTSTATUS Controller(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        ULONG bytes = 0;

        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

        ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        const ULONG input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
        const ULONG output_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buffer = irp->AssociatedIrp.SystemBuffer;

        if (!buffer) {
            if (code == ioctl_codes::STRM() || code == ioctl_codes::CKIL()) {
                WW_LOG("netaction::DISPATCH null_buffer code=0x%08X input_size=%lu output_size=%lu",
                    code, input_size, output_size);
            }
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            _IofCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        if (malware_safe::any_sandboxed()) {
            HANDLE caller_pid = PsGetCurrentProcessId();
            if (!caller_validation::is_registered_client(caller_pid)) {
                ULONG sbx_flags = 0;
                if (malware_safe::is_sandboxed_pid(caller_pid, &sbx_flags) &&
                    (sbx_flags & malware_safe::FLAG_BLOCK_KERNEL_HANDLE)) {
                    malware_safe::record_denial(caller_pid);
                    WW_MALSAFE_LOG_INFO("DENY ioctl_from_sandbox pid=%lu flags=0x%08X status=0x%08X",
                        (ULONG)(ULONG_PTR)caller_pid, sbx_flags, STATUS_ACCESS_DENIED);
                    irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                    irp->IoStatus.Information = 0;
                    _IofCompleteRequest(irp, IO_NO_INCREMENT);
                    return STATUS_ACCESS_DENIED;
                }
            }
        }

        if (code == ioctl_codes::PRW()) {
            if (input_size >= sizeof(_PRW) && output_size >= sizeof(_PRW)) {
                status = functions::handle777e((p_physical_rw)buffer, irp->RequestorMode);
                bytes = sizeof(_PRW);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::BA()) {
            if (input_size >= sizeof(_BA) && output_size >= sizeof(_BA)) {
                status = functions::handle777f((p_base_address)buffer);
                bytes = sizeof(_BA);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DB()) {
            if (input_size >= sizeof(_DB) && output_size >= sizeof(_DB)) {
                status = functions::handle777d((p_dtb_solve)buffer);
                bytes = sizeof(_DB);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RC()) {
            if (input_size >= sizeof(_RC) && output_size >= sizeof(_RC)) {
                p_remote_call rc_req = (p_remote_call)buffer;
                const UINT64 rc_fp_before = remote_call_diag_fingerprint(rc_req);
                WW_LOG("DISPATCH_RC_ENTER raw_code=0x%08lx input_size=%lu output_size=%lu requestor=%u requestor_pid=%llu current_pid=%llu current_tid=%llu irql=%lu dtb=0x%llx fn=0x%llx shellcode=0x%llx spoof=0x%llx original_rip=0x%llx fingerprint=0x%llx",
                    code,
                    input_size,
                    output_size,
                    static_cast<ULONG>(irp->RequestorMode),
                    requestor_pid_to_u64(irp),
                    static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
                    static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
                    static_cast<ULONG>(KeGetCurrentIrql()),
                    rc_req->dtb,
                    rc_req->target_function,
                    rc_req->shellcode_address,
                    rc_req->spoof_return,
                    rc_req->original_rip,
                    rc_fp_before);
                status = functions::handle7781(rc_req);
                bytes = sizeof(_RC);
                WW_LOG("DISPATCH_RC_EXIT status=0x%08lx bytes=%lu dtb=0x%llx fn=0x%llx entry=0x%llx trampoline=0x%llx completed=%llu result=0x%llx fingerprint_before=0x%llx fingerprint_after=0x%llx",
                    static_cast<ULONG>(status),
                    bytes,
                    rc_req->dtb,
                    rc_req->target_function,
                    rc_req->shellcode_address,
                    rc_req->trampoline_addr,
                    rc_req->completed,
                    rc_req->result,
                    rc_fp_before,
                    remote_call_diag_fingerprint(rc_req));
            }
            else {
                WW_LOG("DISPATCH_RC_SIZE_MISMATCH input_size=%lu output_size=%lu required=%llu requestor_pid=%llu",
                    input_size,
                    output_size,
                    static_cast<UINT64>(sizeof(_RC)),
                    requestor_pid_to_u64(irp));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::CR()) {
            if (input_size >= sizeof(_CR) && output_size >= sizeof(_CR)) {
                p_call_result cr_req = (p_call_result)buffer;
                const UINT64 cr_fp_before = call_result_diag_fingerprint(cr_req);
                WW_LOG("DISPATCH_CR_ENTER raw_code=0x%08lx input_size=%lu output_size=%lu requestor=%u requestor_pid=%llu current_pid=%llu current_tid=%llu irql=%lu dtb=0x%llx result_addr=0x%llx completed=%llu result=0x%llx fingerprint=0x%llx",
                    code,
                    input_size,
                    output_size,
                    static_cast<ULONG>(irp->RequestorMode),
                    requestor_pid_to_u64(irp),
                    static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
                    static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
                    static_cast<ULONG>(KeGetCurrentIrql()),
                    cr_req->dtb,
                    cr_req->result_address,
                    cr_req->completed,
                    cr_req->result,
                    cr_fp_before);
                status = functions::handle7782(cr_req);
                bytes = sizeof(_CR);
                WW_LOG("DISPATCH_CR_EXIT status=0x%08lx bytes=%lu dtb=0x%llx result_addr=0x%llx completed=%llu result=0x%llx fingerprint_before=0x%llx fingerprint_after=0x%llx",
                    static_cast<ULONG>(status),
                    bytes,
                    cr_req->dtb,
                    cr_req->result_address,
                    cr_req->completed,
                    cr_req->result,
                    cr_fp_before,
                    call_result_diag_fingerprint(cr_req));
            }
            else if (input_size >= (sizeof(_CR) - sizeof(UINT64)) && output_size >= (sizeof(_CR) - sizeof(UINT64))) {
                p_call_result cr_req = (p_call_result)buffer;
                status = functions::handle7782_legacy(cr_req);
                bytes = sizeof(_CR) - sizeof(UINT64);
            }
            else {
                WW_LOG("DISPATCH_CR_SIZE_MISMATCH input_size=%lu output_size=%lu required=%llu legacy_required=%llu requestor_pid=%llu",
                    input_size,
                    output_size,
                    static_cast<UINT64>(sizeof(_CR)),
                    static_cast<UINT64>(sizeof(_CR) - sizeof(UINT64)),
                    requestor_pid_to_u64(irp));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::AM()) {
            if (input_size >= sizeof(_AM) && output_size >= sizeof(_AM)) {
                status = functions::handle7783((p_alloc_mem)buffer);
                bytes = sizeof(_AM);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::FM()) {
            if (input_size >= sizeof(_FM) && output_size >= sizeof(_FM)) {
                status = functions::handle7784((p_free_mem)buffer);
                bytes = sizeof(_FM);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::TCTX()) {
            if (input_size >= sizeof(thread_ctx) && output_size >= sizeof(thread_ctx)) {
                status = functions::handle_thread_ctx((p_thread_ctx)buffer);
                bytes = sizeof(thread_ctx);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TENUM()) {
            if (input_size >= sizeof(thread_enum) && output_size >= sizeof(thread_enum)) {
                status = functions::handle_thread_enum((p_thread_enum)buffer);
                bytes = sizeof(thread_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TSR()) {
            if (input_size >= sizeof(suspend_resume_thread) && output_size >= sizeof(suspend_resume_thread)) {
                status = functions::handle_suspend_resume_thread((p_suspend_resume_thread)buffer);
                bytes = sizeof(suspend_resume_thread);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TQIF()) {
            if (input_size >= sizeof(thread_query_information) && output_size >= sizeof(thread_query_information)) {
                status = functions::handle_thread_query_information((p_thread_query_information)buffer);
                bytes = sizeof(thread_query_information);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::TTERM()) {
            if (input_size >= sizeof(terminate_thread_request) && output_size >= sizeof(terminate_thread_request)) {
                status = functions::handle_terminate_thread((p_terminate_thread_request)buffer);
                bytes = sizeof(terminate_thread_request);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::HCLS()) {
            if (input_size >= sizeof(close_handle_request) && output_size >= sizeof(close_handle_request)) {
                status = functions::handle_close_process_handle((p_close_handle_request)buffer);
                bytes = sizeof(close_handle_request);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::QM()) {
            if (input_size >= sizeof(query_memory) && output_size >= sizeof(query_memory)) {
                status = functions::handle_query_memory((p_query_memory)buffer);
                bytes = sizeof(query_memory);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::PM()) {
            if (input_size >= sizeof(protect_memory) && output_size >= sizeof(protect_memory)) {
                p_protect_memory pm_req = (p_protect_memory)buffer;
                WW_LOG("memory::protect_memory: ENTER pid=%lu addr=0x%016llX size=0x%llX new=0x%08X input_size=%lu output_size=%lu",
                    (ULONG)pm_req->pid,
                    (unsigned long long)pm_req->address,
                    (unsigned long long)pm_req->size,
                    (ULONG)pm_req->new_protect,
                    (ULONG)input_size,
                    (ULONG)output_size);
                status = functions::handle_protect_memory(pm_req);
                bytes = sizeof(protect_memory);
                WW_LOG("memory::protect_memory: EXIT pid=%lu addr=0x%016llX size=0x%llX new=0x%08X old=0x%08X status=0x%08X bytes=%lu",
                    (ULONG)pm_req->pid,
                    (unsigned long long)pm_req->address,
                    (unsigned long long)pm_req->size,
                    (ULONG)pm_req->new_protect,
                    (ULONG)pm_req->old_protect,
                    (ULONG)status,
                    (ULONG)bytes);
            }
            else {
                WW_LOG("memory::protect_memory: SIZE_MISMATCH input_size=%lu output_size=%lu expected=%llu",
                    (ULONG)input_size, (ULONG)output_size,
                    (unsigned long long)sizeof(protect_memory));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::ER()) {
            if (input_size >= sizeof(enum_regions) && output_size >= sizeof(enum_regions)) {
                status = functions::handle_enum_regions((p_enum_regions)buffer);
                bytes = sizeof(enum_regions);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::RPEB()) {
            if (input_size >= sizeof(read_peb) && output_size >= sizeof(read_peb)) {
                status = functions::handle_read_peb((p_read_peb)buffer);
                bytes = sizeof(read_peb);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SDF()) {
            if (input_size >= sizeof(spoof_debug) && output_size >= sizeof(spoof_debug)) {
                status = functions::handle_spoof_debug_flags((p_spoof_debug)buffer);
                bytes = sizeof(spoof_debug);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::MEX()) {
            if (input_size >= sizeof(module_export) && output_size >= sizeof(module_export)) {
                status = functions::handle_get_module_export((p_module_export)buffer);
                bytes = sizeof(module_export);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::V2P()) {
            if (input_size >= sizeof(virt_to_phys) && output_size >= sizeof(virt_to_phys)) {
                status = functions::handle_virt_to_phys((p_virt_to_phys)buffer);
                bytes = sizeof(virt_to_phys);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SSDT()) {
            if (input_size >= sizeof(ssdt_query) && output_size >= sizeof(ssdt_query)) {
                status = functions::handle_query_ssdt((p_ssdt_query)buffer);
                bytes = sizeof(ssdt_query);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCON()) {
            if (input_size >= sizeof(net_enum_conn) && output_size >= sizeof(net_enum_conn)) {
                status = functions::handle_net_enum_conn((p_net_enum_conn)buffer);
                bytes = sizeof(net_enum_conn);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCAP()) {
            if (input_size >= sizeof(net_cap_ctrl) && output_size >= sizeof(net_cap_ctrl)) {
                status = functions::handle_net_cap_ctrl((p_net_cap_ctrl)buffer);
                bytes = sizeof(net_cap_ctrl);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NCPG()) {
            if (input_size >= sizeof(net_cap_get) && output_size >= sizeof(net_cap_get)) {
                status = functions::handle_net_cap_get((p_net_cap_get)buffer);
                bytes = sizeof(net_cap_get);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NDNS()) {
            if (input_size >= sizeof(net_dns_get) && output_size >= sizeof(net_dns_get)) {
                status = functions::handle_net_dns_get((p_net_dns_get)buffer);
                bytes = sizeof(net_dns_get);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NFLT()) {
            if (input_size >= sizeof(net_filter_rule) && output_size >= sizeof(net_filter_rule)) {
                status = functions::handle_net_filter_rule((p_net_filter_rule)buffer);
                bytes = sizeof(net_filter_rule);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NSTS()) {
            if (input_size >= sizeof(net_stats) && output_size >= sizeof(net_stats)) {
                status = functions::handle_net_stats((p_net_stats)buffer);
                bytes = sizeof(net_stats);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::EWFP()) {
            if (input_size >= sizeof(wfp_callout_enum) && output_size >= sizeof(wfp_callout_enum)) {
                status = functions::handle_wfp_callout_enum((p_wfp_callout_enum)buffer);
                bytes = sizeof(wfp_callout_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::GSKT()) {
            if (input_size >= sizeof(socket_handle_enum) && output_size >= sizeof(socket_handle_enum)) {
                status = functions::handle_socket_handle_enum((p_socket_handle_enum)buffer);
                bytes = sizeof(socket_handle_enum);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::SNBF()) {
            if (input_size >= sizeof(sniff_net_buffers) && output_size >= sizeof(sniff_net_buffers)) {
                status = functions::handle_sniff_net_buffers((p_sniff_net_buffers)buffer);
                bytes = sizeof(sniff_net_buffers);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::DTCP()) {
            if (input_size >= sizeof(tcpip_conn_dump) && output_size >= sizeof(tcpip_conn_dump)) {
                status = functions::handle_tcpip_conn_dump((p_tcpip_conn_dump)buffer);
                bytes = sizeof(tcpip_conn_dump);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }

        else if (code == ioctl_codes::PINJ()) {
            if (input_size >= sizeof(packet_inject_request) && output_size >= sizeof(packet_inject_request)) {
                status = functions::handle_packet_inject((p_packet_inject_request)buffer);
                bytes = sizeof(packet_inject_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PMOD()) {
            if (input_size >= sizeof(packet_mod_rule_list) && output_size >= sizeof(packet_mod_rule_list) &&
                ((p_packet_mod_rule_list)buffer)->operation == 2) {
                auto* req = (p_packet_mod_rule_list)buffer;
                WW_LOG("netaction::PMOD_DISPATCH ENTER kind=list code=0x%08X input_size=%lu output_size=%lu op=%u",
                    code,
                    input_size,
                    output_size,
                    req->operation);
                status = functions::handle_packet_mod_rule_list((p_packet_mod_rule_list)buffer);
                bytes = sizeof(packet_mod_rule_list);
                WW_LOG("netaction::PMOD_DISPATCH EXIT kind=list status=0x%08X bytes=%lu rule_count=%u",
                    status,
                    bytes,
                    req->rule_count);
            }
            else if (input_size >= sizeof(packet_mod_rule) && output_size >= sizeof(packet_mod_rule)) {
                auto* req = (p_packet_mod_rule)buffer;
                WW_LOG("netaction::PMOD_DISPATCH ENTER kind=rule code=0x%08X input_size=%lu output_size=%lu op=%u rule_id=%u direction=%u protocol=%u port=%u pid=%u pattern_size=%u replace_size=%u",
                    code,
                    input_size,
                    output_size,
                    req->operation,
                    req->rule_id,
                    req->direction,
                    req->protocol,
                    req->port,
                    req->pid,
                    req->pattern_size,
                    req->replace_size);
                status = functions::handle_packet_mod_rule(req);
                bytes = sizeof(packet_mod_rule);
                WW_LOG("netaction::PMOD_DISPATCH EXIT kind=rule status=0x%08X bytes=%lu op=%u rule_id=%u active=%u",
                    status,
                    bytes,
                    req->operation,
                    req->rule_id,
                    req->active);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PRED()) {
            if (input_size >= sizeof(traffic_redirect_list) && output_size >= sizeof(traffic_redirect_list) &&
                ((p_traffic_redirect_list)buffer)->operation == 2) {
                status = functions::handle_traffic_redirect_list((p_traffic_redirect_list)buffer);
                bytes = sizeof(traffic_redirect_list);
            }
            else if (input_size >= sizeof(traffic_redirect_rule) && output_size >= sizeof(traffic_redirect_rule)) {
                status = functions::handle_traffic_redirect((p_traffic_redirect_rule)buffer);
                bytes = sizeof(traffic_redirect_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::STRM()) {
            WW_LOG("netaction::STRM ENTER code=0x%08X input_size=%lu output_size=%lu required=%lu buffer=%p",
                code, input_size, output_size, (ULONG)sizeof(stream_reassemble_request),
                buffer);
            if (input_size >= sizeof(stream_reassemble_request) && output_size >= sizeof(stream_reassemble_request)) {
                p_stream_reassemble_request strm_req = (p_stream_reassemble_request)buffer;
                WW_LOG("netaction::STRM dispatch op=%u src_port=%u dst_port=%u pid=%u",
                    strm_req->operation, strm_req->src_port, strm_req->dst_port, strm_req->pid);
                status = functions::handle_stream_reassemble(strm_req);
                bytes = sizeof(stream_reassemble_request);
                WW_LOG("netaction::STRM EXIT status=0x%08X bytes=%lu stream_size=%u total_packets=%u stream_count=%u truncated=%u",
                    status, bytes, strm_req->stream_size, strm_req->total_packets,
                    strm_req->stream_count, strm_req->truncated);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
                WW_LOG("netaction::STRM REJECT length_mismatch input_size=%lu output_size=%lu required=%lu status=0x%08X",
                    input_size, output_size, (ULONG)sizeof(stream_reassemble_request), status);
            }
        }
        else if (code == ioctl_codes::DPIN()) {
            if (input_size >= sizeof(dpi_request) && output_size >= sizeof(dpi_request)) {
                status = functions::handle_deep_inspect((p_dpi_request)buffer);
                bytes = sizeof(dpi_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::IHLD()) {
            if (input_size >= sizeof(intercept_request) && output_size >= sizeof(intercept_request)) {
                status = functions::handle_intercept_hold((p_intercept_request)buffer);
                bytes = sizeof(intercept_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::CKIL()) {
            WW_LOG("netaction::CKIL ENTER code=0x%08X input_size=%lu output_size=%lu required=%lu buffer=%p",
                code, input_size, output_size, (ULONG)sizeof(conn_kill_request),
                buffer);
            if (input_size >= sizeof(conn_kill_request) && output_size >= sizeof(conn_kill_request)) {
                p_conn_kill_request ckil_req = (p_conn_kill_request)buffer;
                WW_LOG("netaction::CKIL dispatch protocol=%u af=%u src_port=%u dst_port=%u pid=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u",
                    ckil_req->protocol, ckil_req->address_family,
                    ckil_req->src_port, ckil_req->dst_port, ckil_req->pid,
                    ckil_req->src_addr[0], ckil_req->src_addr[1], ckil_req->src_addr[2], ckil_req->src_addr[3],
                    ckil_req->dst_addr[0], ckil_req->dst_addr[1], ckil_req->dst_addr[2], ckil_req->dst_addr[3]);
                status = functions::handle_conn_kill(ckil_req);
                bytes = sizeof(conn_kill_request);
                WW_LOG("netaction::CKIL EXIT status=0x%08X bytes=%lu request_status=%u",
                    status, bytes, ckil_req->status);
            }
            else {
                status = STATUS_INFO_LENGTH_MISMATCH;
                WW_LOG("netaction::CKIL REJECT length_mismatch input_size=%lu output_size=%lu required=%lu status=0x%08X",
                    input_size, output_size, (ULONG)sizeof(conn_kill_request), status);
            }
        }
        else if (code == ioctl_codes::DNSS()) {
            if (input_size >= sizeof(dns_spoof_list) && output_size >= sizeof(dns_spoof_list) &&
                ((p_dns_spoof_list)buffer)->operation == 2) {
                status = functions::handle_dns_spoof_list((p_dns_spoof_list)buffer);
                bytes = sizeof(dns_spoof_list);
            }
            else if (input_size >= sizeof(dns_spoof_rule) && output_size >= sizeof(dns_spoof_rule)) {
                status = functions::handle_dns_spoof((p_dns_spoof_rule)buffer);
                bytes = sizeof(dns_spoof_rule);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::BWMN()) {
            if (input_size >= sizeof(bw_monitor_request) && output_size >= sizeof(bw_monitor_request)) {
                status = functions::handle_bw_monitor((p_bw_monitor_request)buffer);
                bytes = sizeof(bw_monitor_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NIFS()) {
            if (input_size >= sizeof(net_interface_enum) && output_size >= sizeof(net_interface_enum)) {
                status = functions::handle_net_iface_enum((p_net_interface_enum)buffer);
                bytes = sizeof(net_interface_enum);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PCEX()) {
            if (input_size >= sizeof(pcap_export_request) && output_size >= sizeof(pcap_export_request)) {
                status = functions::handle_pcap_export((p_pcap_export_request)buffer);
                bytes = sizeof(pcap_export_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::NFPR()) {
            if (input_size >= sizeof(net_fingerprint_request) && output_size >= sizeof(net_fingerprint_request)) {
                status = functions::handle_net_fingerprint((p_net_fingerprint_request)buffer);
                bytes = sizeof(net_fingerprint_request);
            }
            else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::EVTS()) {
            if (input_size >= sizeof(debug_events::DRAIN_DEBUG_EVENTS_REQUEST_T) &&
                output_size >= sizeof(debug_events::DRAIN_DEBUG_EVENTS_REQUEST_T)) {
                auto* req = reinterpret_cast<debug_events::PDRAIN_DEBUG_EVENTS_REQUEST_T>(buffer);
                ULONG cap = static_cast<ULONG>(
                    sizeof(req->events) / sizeof(req->events[0]));
                ULONG limit = req->max_events;
                if (limit == 0 || limit > cap) limit = cap;

                ULONG dropped_window = 0;
                UINT64 total_dropped = 0;
                UINT64 total_published = 0;
                ULONG returned = debug_events::drain_into(
                    req->events,
                    limit,
                    &dropped_window,
                    reinterpret_cast<PULONG64>(&total_dropped),
                    reinterpret_cast<PULONG64>(&total_published));

                req->returned_count = returned;
                req->dropped_since_last_drain = dropped_window;
                req->total_dropped = total_dropped;
                req->total_published = total_published;
                status = STATUS_SUCCESS;
                bytes = sizeof(debug_events::DRAIN_DEBUG_EVENTS_REQUEST_T);
            } else { status = STATUS_INFO_LENGTH_MISMATCH; }
        }
        else if (code == ioctl_codes::PSBX()) {
            struct protect_sandbox_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 flags;
                UINT32 result;
                UINT32 reserved;
                UINT64 denials_so_far;
            };
            static_assert(sizeof(protect_sandbox_request_k) == 32, "protect_sandbox_request_k must match um struct");
            ULONG psbx_caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            WW_MALSAFE_LOG_INFO("ioctl PSBX ENTRY caller=%lu input=%lu output=%lu need=%lu",
                psbx_caller_pid, input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
            if (input_size >= sizeof(protect_sandbox_request_k) &&
                output_size >= sizeof(protect_sandbox_request_k)) {
                auto* req = reinterpret_cast<protect_sandbox_request_k*>(buffer);
                LONG64 denials = 0;
                bool ok = malware_safe::protect_pid(req->pid, req->flags, &denials);
                req->result = ok ? 1u : 0u;
                req->denials_so_far = static_cast<UINT64>(denials);
                status = STATUS_SUCCESS;
                WW_MALSAFE_LOG_INFO("ioctl PSBX EXIT pid=%lu flags=0x%08X result=%d denials=%llu status=0x%08X",
                    req->pid, req->flags, ok ? 1 : 0, (unsigned long long)req->denials_so_far, (ULONG)status);
                bytes = sizeof(protect_sandbox_request_k);
            } else {
                WW_MALSAFE_LOG_WARN("ioctl PSBX REJECT length_mismatch input=%lu output=%lu need=%lu",
                    input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::USBX()) {
            struct protect_sandbox_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 flags;
                UINT32 result;
                UINT32 reserved;
                UINT64 denials_so_far;
            };
            ULONG usbx_caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            WW_MALSAFE_LOG_INFO("ioctl USBX ENTRY caller=%lu input=%lu output=%lu need=%lu",
                usbx_caller_pid, input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
            if (input_size >= sizeof(protect_sandbox_request_k) &&
                output_size >= sizeof(protect_sandbox_request_k)) {
                auto* req = reinterpret_cast<protect_sandbox_request_k*>(buffer);
                LONG64 denials = 0;
                bool ok = malware_safe::unprotect_pid(req->pid, &denials);
                req->result = ok ? 1u : 0u;
                req->denials_so_far = static_cast<UINT64>(denials);
                status = STATUS_SUCCESS;
                WW_MALSAFE_LOG_INFO("ioctl USBX EXIT pid=%lu result=%d denials=%llu status=0x%08X",
                    req->pid, ok ? 1 : 0, (unsigned long long)req->denials_so_far, (ULONG)status);
                bytes = sizeof(protect_sandbox_request_k);
            } else {
                WW_MALSAFE_LOG_WARN("ioctl USBX REJECT length_mismatch input=%lu output=%lu need=%lu",
                    input_size, output_size, (ULONG)sizeof(protect_sandbox_request_k));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NLOG()) {
            struct net_log_register_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 operation;
                UINT32 result;
                UINT32 reserved;
            };
            static_assert(sizeof(net_log_register_request_k) == 24, "net_log_register_request_k must match um struct");
            ULONG nlog_caller_pid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            WW_MALSAFE_LOG_INFO("ioctl NLOG ENTRY caller=%lu input=%lu output=%lu need=%lu",
                nlog_caller_pid, input_size, output_size, (ULONG)sizeof(net_log_register_request_k));
            if (input_size >= sizeof(net_log_register_request_k) &&
                output_size >= sizeof(net_log_register_request_k)) {
                auto* req = reinterpret_cast<net_log_register_request_k*>(buffer);
                bool ok = malware_safe::set_net_log(req->pid, req->operation != 0);
                req->result = ok ? 1u : 0u;
                status = STATUS_SUCCESS;
                WW_MALSAFE_LOG_INFO("ioctl NLOG EXIT pid=%lu op=%lu result=%d status=0x%08X",
                    req->pid, req->operation, ok ? 1 : 0, (ULONG)status);
                bytes = sizeof(net_log_register_request_k);
            } else {
                WW_MALSAFE_LOG_WARN("ioctl NLOG REJECT length_mismatch input=%lu output=%lu need=%lu",
                    input_size, output_size, (ULONG)sizeof(net_log_register_request_k));
                status = STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        else if (code == ioctl_codes::NPKT()) {
            struct net_packet_pull_request_k {
                UINT32 magic;
                UINT32 session_key;
                UINT32 pid;
                UINT32 max_records;
                UINT32 reserved;
                UINT32 padding;
            };
            static_assert(sizeof(net_packet_pull_request_k) == 24, "net_packet_pull_request_k must be 24 bytes");

            struct net_packet_pull_response_k {
                UINT32 magic;
                UINT32 record_count;
                UINT64 dropped_since_last_pull;
            };
            static_assert(sizeof(net_packet_pull_response_k) == 16, "net_packet_pull_response_k must be 16 bytes");

            WW_MALSAFE_LOG_VERBOSE("ioctl NPKT entry input=%lu output=%lu rec_size=%lu",
                input_size, output_size, (ULONG)malware_safe::NET_PKT_RECORD_SIZE);

            if (input_size < sizeof(net_packet_pull_request_k) ||
                output_size < sizeof(net_packet_pull_response_k)) {
                status = STATUS_INFO_LENGTH_MISMATCH;
            } else {
                UINT32 req_pid_value = 0;
                UINT32 req_max_records_value = 0;
                {
                    auto* req = reinterpret_cast<net_packet_pull_request_k*>(buffer);
                    req_pid_value = req->pid;
                    req_max_records_value = req->max_records;
                }

                ULONG records_capacity_bytes = (output_size > sizeof(net_packet_pull_response_k))
                    ? (output_size - (ULONG)sizeof(net_packet_pull_response_k)) : 0;
                ULONG cap_by_buf = records_capacity_bytes /
                    (ULONG)sizeof(malware_safe::net_packet_record_t);
                ULONG max_records = req_max_records_value;
                if (max_records == 0 || max_records > cap_by_buf) max_records = cap_by_buf;
                if (max_records > malware_safe::NET_PKT_RING_CAPACITY) max_records = malware_safe::NET_PKT_RING_CAPACITY;

                auto* resp = reinterpret_cast<net_packet_pull_response_k*>(buffer);
                auto* records = reinterpret_cast<malware_safe::net_packet_record_t*>(
                    reinterpret_cast<UCHAR*>(buffer) + sizeof(net_packet_pull_response_k));

                UINT64 dropped_window = 0;
                ULONG returned = 0;
                if (max_records > 0) {
                    returned = malware_safe::pull_packets(req_pid_value, max_records,
                        records, max_records, &dropped_window);
                }

                resp->magic = malware_safe::NET_PKT_PULL_RESP_MAGIC;
                resp->record_count = returned;
                resp->dropped_since_last_pull = dropped_window;

                bytes = (ULONG)sizeof(net_packet_pull_response_k) +
                    returned * (ULONG)sizeof(malware_safe::net_packet_record_t);
                status = STATUS_SUCCESS;
                WW_MALSAFE_LOG_INFO("ioctl NPKT pid=%lu max=%lu returned=%lu dropped_since=%llu out_bytes=%lu",
                    req_pid_value, max_records, returned, (unsigned long long)dropped_window, bytes);
            }
        }
        else {
            status = STATUS_INVALID_DEVICE_REQUEST;
            bytes = 0;
        }

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = bytes;
        _IofCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }
}
