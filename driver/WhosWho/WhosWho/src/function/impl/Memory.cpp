#include <function/Functions.h>
#include "driver/Strong.h"
#include <imports/Defs.h>
#include <function/CoreSecurity.h>

namespace mem_guard {
    inline volatile ULONG g_mem_entropy = 0xC0DEBEEFu;

    __forceinline void timing_scatter() {
        ULONG x = g_mem_entropy ^ (ULONG)(__rdtsc() & 0x1FFu);
        x ^= x << 13;
        g_mem_entropy = x;
        if ((x & 0xF) < 3) {
            volatile ULONG spin = (x & 0x3) + 1;
            while (spin--) YieldProcessor();
        }
    }

    __forceinline BOOLEAN is_valid_user_range(UINT64 addr) {
        return (addr > 0x10000ULL && addr < 0x00007FFFFFFFFFFFULL);
    }

    __forceinline BOOLEAN is_safe_size(SIZE_T size) {
        return (size > 0 && size <= 0x1000000);
    }

    __forceinline UINT64 elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart == 0) {
            return 0;
        }
        return (UINT64)(((now.QuadPart - start.QuadPart) * 1000000LL) / freq.QuadPart);
    }

    struct page_walk_diag_t {
        BOOLEAN pml4_ok = FALSE;
        BOOLEAN pdpt_ok = FALSE;
        BOOLEAN pde_ok = FALSE;
        BOOLEAN pte_ok = FALSE;
        BOOLEAN present = FALSE;
        UINT32 level = 0;
        UINT64 pml4e = 0;
        UINT64 pdpte = 0;
        UINT64 pde = 0;
        UINT64 pte = 0;
        UINT64 physical = 0;
        UINT64 remaining = 0;
    };

    __forceinline BOOLEAN read_phys_u64(UINT64 pa, UINT64* out) {
        if (!out) {
            return FALSE;
        }
        SIZE_T bytes = 0;
        *out = 0;
        NTSTATUS status = strong::read_physical(pa, out, sizeof(UINT64), &bytes);
        return NT_SUCCESS(status) && bytes == sizeof(UINT64);
    }

    __forceinline page_walk_diag_t capture_page_walk(UINT64 dtb, UINT64 va) {
        page_walk_diag_t d{};
        UINT64 cr3 = dtb & PMASK;
        if (cr3 == 0) {
            return d;
        }
        const UINT64 offset = va & 0xFFFULL;
        const UINT64 pte_index = (va >> 12) & 0x1FFULL;
        const UINT64 pde_index = (va >> 21) & 0x1FFULL;
        const UINT64 pdpte_index = (va >> 30) & 0x1FFULL;
        const UINT64 pml4e_index = (va >> 39) & 0x1FFULL;
        d.pml4_ok = read_phys_u64(cr3 + pml4e_index * 8ULL, &d.pml4e);
        if (!d.pml4_ok || (d.pml4e & 1ULL) == 0) {
            return d;
        }
        d.pdpt_ok = read_phys_u64((d.pml4e & PMASK) + pdpte_index * 8ULL, &d.pdpte);
        if (!d.pdpt_ok || (d.pdpte & 1ULL) == 0) {
            return d;
        }
        if ((d.pdpte & (1ULL << 7)) != 0) {
            d.present = TRUE;
            d.level = 1;
            d.physical = (d.pdpte & 0x000FFFFFC0000000ULL) + (va & 0x3FFFFFFFULL);
            d.remaining = 0x40000000ULL - (va & 0x3FFFFFFFULL);
            return d;
        }
        d.pde_ok = read_phys_u64((d.pdpte & PMASK) + pde_index * 8ULL, &d.pde);
        if (!d.pde_ok || (d.pde & 1ULL) == 0) {
            return d;
        }
        if ((d.pde & (1ULL << 7)) != 0) {
            d.present = TRUE;
            d.level = 2;
            d.physical = (d.pde & 0x000FFFFFFFE00000ULL) + (va & 0x1FFFFFULL);
            d.remaining = 0x200000ULL - (va & 0x1FFFFFULL);
            return d;
        }
        d.pte_ok = read_phys_u64((d.pde & PMASK) + pte_index * 8ULL, &d.pte);
        if (!d.pte_ok || (d.pte & 1ULL) == 0) {
            return d;
        }
        d.present = TRUE;
        d.level = 4;
        d.physical = (d.pte & PMASK) + offset;
        d.remaining = 0x1000ULL - offset;
        return d;
    }

    __forceinline void log_page_walk(const char* phase, UINT32 pid, UINT64 dtb, UINT64 va, const page_walk_diag_t& d, UINT64 strong_pa) {
        WW_LOG("PHYS_RW_PAGE_WALK phase=%s pid=%lu dtb=0x%llx va=0x%llx strong_pa=0x%llx walk_pa=0x%llx level=%lu remaining=0x%llx pml4_ok=%u pdpt_ok=%u pde_ok=%u pte_ok=%u present=%u pml4e=0x%llx pdpte=0x%llx pde=0x%llx pte=0x%llx pml4_p=%u pml4_w=%u pml4_u=%u pml4_nx=%u pdpt_p=%u pdpt_w=%u pdpt_u=%u pdpt_l=%u pdpt_nx=%u pde_p=%u pde_w=%u pde_u=%u pde_l=%u pde_nx=%u pte_p=%u pte_w=%u pte_u=%u pte_nx=%u",
            phase ? phase : "<null>",
            (ULONG)pid,
            dtb,
            va,
            strong_pa,
            d.physical,
            (ULONG)d.level,
            d.remaining,
            d.pml4_ok ? 1u : 0u,
            d.pdpt_ok ? 1u : 0u,
            d.pde_ok ? 1u : 0u,
            d.pte_ok ? 1u : 0u,
            d.present ? 1u : 0u,
            d.pml4e,
            d.pdpte,
            d.pde,
            d.pte,
            (d.pml4e & 1ULL) ? 1u : 0u,
            (d.pml4e & 2ULL) ? 1u : 0u,
            (d.pml4e & 4ULL) ? 1u : 0u,
            (d.pml4e & (1ULL << 63)) ? 1u : 0u,
            (d.pdpte & 1ULL) ? 1u : 0u,
            (d.pdpte & 2ULL) ? 1u : 0u,
            (d.pdpte & 4ULL) ? 1u : 0u,
            (d.pdpte & (1ULL << 7)) ? 1u : 0u,
            (d.pdpte & (1ULL << 63)) ? 1u : 0u,
            (d.pde & 1ULL) ? 1u : 0u,
            (d.pde & 2ULL) ? 1u : 0u,
            (d.pde & 4ULL) ? 1u : 0u,
            (d.pde & (1ULL << 7)) ? 1u : 0u,
            (d.pde & (1ULL << 63)) ? 1u : 0u,
            (d.pte & 1ULL) ? 1u : 0u,
            (d.pte & 2ULL) ? 1u : 0u,
            (d.pte & 4ULL) ? 1u : 0u,
            (d.pte & (1ULL << 63)) ? 1u : 0u);
    }

    __forceinline BOOLEAN physical_readback_matches(UINT64 physical_address, PVOID expected, SIZE_T size, SIZE_T* out_checked, NTSTATUS* out_status, SIZE_T* out_read, ULONG* out_mismatch) {
        UCHAR readback[64] = {};
        UCHAR expected_copy[64] = {};
        const SIZE_T check_size = size < sizeof(readback) ? size : sizeof(readback);
        SIZE_T bytes_read = 0;
        if (out_checked) *out_checked = check_size;
        if (out_read) *out_read = 0;
        if (out_mismatch) *out_mismatch = 0xFFFFFFFFUL;
        if (out_status) *out_status = STATUS_INVALID_PARAMETER;
        if (!expected || check_size == 0) {
            return FALSE;
        }
        __try {
            strong::kmemcpy(expected_copy, expected, check_size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            if (out_status) *out_status = (NTSTATUS)GetExceptionCode();
            if (out_mismatch) *out_mismatch = 0xFFFFFFFEUL;
            return FALSE;
        }
        NTSTATUS status = strong::read_physical(physical_address, readback, check_size, &bytes_read);
        if (out_status) *out_status = status;
        if (out_read) *out_read = bytes_read;
        if (!NT_SUCCESS(status) || bytes_read != check_size) {
            return FALSE;
        }
        for (SIZE_T i = 0; i < check_size; ++i) {
            if (readback[i] != expected_copy[i]) {
                if (out_mismatch) *out_mismatch = (ULONG)i;
                return FALSE;
            }
        }
        return TRUE;
    }
}

NTSTATUS functions::handle777e(p_physical_rw request, KPROCESSOR_MODE requestor_mode) {
    LARGE_INTEGER freq{};
    LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
    if (!request) {
        WW_LOG("PHYS_RW_REJECT reason=request_null status=0x%08X cpu=%lu irql=%lu qpc=%lld tsc=%llu",
            (ULONG)STATUS_INVALID_PARAMETER,
            KeGetCurrentProcessorNumber(),
            (ULONG)KeGetCurrentIrql(),
            start.QuadPart,
            __rdtsc());
        return STATUS_INVALID_PARAMETER;
    }

    mem_guard::timing_scatter();

    WW_LOG("PHYS_RW_ENTER pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u buffer=0x%llx requestor_pid=%llu current_pid=%llu current_tid=%llu irql=%lu qpc=%lld tsc=%llu",
        (ULONG)request->pid,
        request->dtb,
        (UINT64)request->address,
        (UINT64)request->size,
        request->shouldWrite ? 1u : 0u,
        (UINT64)request->buffer,
        (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
        (UINT64)(ULONG_PTR)PsGetCurrentProcessId(),
        (UINT64)(ULONG_PTR)PsGetCurrentThreadId(),
        (ULONG)KeGetCurrentIrql(),
        start.QuadPart,
        __rdtsc());

    if (!request->buffer || request->size == 0 ||
        request->size - 1 > MAXUINT64 - (UINT64)request->address ||
        request->size - 1 > MAXUINT64 - (UINT64)request->buffer) {
        WW_LOG("PHYS_RW_EXIT pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u status=0x%08X ret=0 reason=bad_buffer_or_size elapsed_us=%llu",
            (ULONG)request->pid,
            request->dtb,
            (UINT64)request->address,
            (UINT64)request->size,
            request->shouldWrite ? 1u : 0u,
            (ULONG)STATUS_INVALID_PARAMETER,
            mem_guard::elapsed_us(start, freq));
        return STATUS_INVALID_PARAMETER;
    }

    if (request->dtb == 0) {
        WW_LOG("PHYS_RW_EXIT pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u status=0x%08X ret=0 reason=dtb_zero elapsed_us=%llu",
            (ULONG)request->pid,
            request->dtb,
            (UINT64)request->address,
            (UINT64)request->size,
            request->shouldWrite ? 1u : 0u,
            (ULONG)STATUS_INVALID_PARAMETER,
            mem_guard::elapsed_us(start, freq));
        return STATUS_INVALID_PARAMETER;
    }

    if (request->size > 0x4000000) {
        WW_LOG("PHYS_RW_EXIT pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u status=0x%08X ret=0 reason=size_too_large elapsed_us=%llu",
            (ULONG)request->pid,
            request->dtb,
            (UINT64)request->address,
            (UINT64)request->size,
            request->shouldWrite ? 1u : 0u,
            (ULONG)STATUS_INVALID_BUFFER_SIZE,
            mem_guard::elapsed_us(start, freq));
        return STATUS_INVALID_BUFFER_SIZE;
    }

    const UINT64 target_addr = (UINT64)request->address;
    if (target_addr == 0) {
        WW_LOG("PHYS_RW_EXIT pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u status=0x%08X ret=0 reason=target_zero elapsed_us=%llu",
            (ULONG)request->pid,
            request->dtb,
            (UINT64)request->address,
            (UINT64)request->size,
            request->shouldWrite ? 1u : 0u,
            (ULONG)STATUS_ACCESS_DENIED,
            mem_guard::elapsed_us(start, freq));
        return STATUS_ACCESS_DENIED;
    }


    const UINT64 process_dir_base = request->dtb;
    const UINT32 target_pid = request->pid;
    const BOOLEAN is_write = (request->shouldWrite != 0);

    const BOOLEAN softfault_eligible =
        (!is_write) &&
        (KeGetCurrentIrql() == PASSIVE_LEVEL) &&
        (target_pid != 0) &&
        (_PsLookupProcessByProcessId != nullptr) &&
        (_KeStackAttachProcess != nullptr) &&
        (_KeUnstackDetachProcess != nullptr) &&
        (_ObfDereferenceObject != nullptr);

    SIZE_T total_bytes_transferred = 0;
    SIZE_T remaining_size = request->size;
    SIZE_T current_offset = 0;

    PEPROCESS target_proc = nullptr;
    BOOLEAN proc_lookup_attempted = FALSE;
    PVOID km_staging = nullptr;
    NTSTATUS final_status = STATUS_UNSUCCESSFUL;

    while (remaining_size > 0) {
        const UINT64 current_virtual_address = (UINT64)request->address + current_offset;


        const SIZE_T page_remaining = 0x1000 - (current_virtual_address & 0xFFF);
        const SIZE_T transfer_size = (page_remaining < remaining_size) ? page_remaining : remaining_size;

        const mem_guard::page_walk_diag_t walk = mem_guard::capture_page_walk(process_dir_base, current_virtual_address);
        const UINT64 physical_address = strong::translate_virtual_address(process_dir_base, current_virtual_address);
        mem_guard::log_page_walk(is_write ? "write" : "read", target_pid, process_dir_base, current_virtual_address, walk, physical_address);
        BOOLEAN chunk_done = FALSE;

        if (!km_staging) {
            km_staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'sFwW');
            if (!km_staging) {
                final_status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
        }

        PVOID current_buffer = (PVOID)((ULONG_PTR)request->buffer + current_offset);
        __try {
            if (requestor_mode != KernelMode) {
                if (is_write) {
                    ProbeForRead(current_buffer, transfer_size, 1);
                    strong::kmemcpy(km_staging, current_buffer, transfer_size);
                } else {
                    ProbeForWrite(current_buffer, transfer_size, 1);
                }
            } else if (is_write) {
                strong::kmemcpy(km_staging, current_buffer, transfer_size);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            final_status = (NTSTATUS)GetExceptionCode();
            break;
        }

        if (physical_address) {
            SIZE_T bytes_transferred = 0;
            NTSTATUS operation_status = STATUS_UNSUCCESSFUL;

            if (is_write) {
                operation_status = strong::write_physical(
                    (PVOID)physical_address,
                    km_staging,
                    transfer_size,
                    &bytes_transferred
                );
                SIZE_T checked = 0;
                SIZE_T readback_bytes = 0;
                ULONG mismatch = 0xFFFFFFFFUL;
                NTSTATUS readback_status = STATUS_UNSUCCESSFUL;
                BOOLEAN readback_match = FALSE;
                if (NT_SUCCESS(operation_status) && bytes_transferred > 0) {
                    readback_match = mem_guard::physical_readback_matches(
                        physical_address,
                        km_staging,
                        bytes_transferred,
                        &checked,
                        &readback_status,
                        &readback_bytes,
                        &mismatch);
                    WW_LOG("PHYS_RW_WRITE_READBACK pid=%lu dtb=0x%llx va=0x%llx pa=0x%llx requested=0x%llx written=0x%llx checked=0x%llx readback_bytes=0x%llx match=%u mismatch=%lu write_status=0x%08X read_status=0x%08X elapsed_us=%llu",
                        (ULONG)target_pid,
                        process_dir_base,
                        current_virtual_address,
                        physical_address,
                        (UINT64)transfer_size,
                        (UINT64)bytes_transferred,
                        (UINT64)checked,
                        (UINT64)readback_bytes,
                        readback_match ? 1u : 0u,
                        mismatch,
                        (ULONG)operation_status,
                        (ULONG)readback_status,
                        mem_guard::elapsed_us(start, freq));
                    if (!readback_match) {
                        operation_status = STATUS_DATA_ERROR;
                        bytes_transferred = 0;
                    }
                }
            }
            else {
                operation_status = strong::read_physical(
                    physical_address,
                    km_staging,
                    transfer_size,
                    &bytes_transferred
                );
            }

            WW_LOG("PHYS_RW_CHUNK pid=%lu dtb=0x%llx va=0x%llx pa=0x%llx requested=0x%llx should_write=%u status=0x%08X bytes=0x%llx total_before=0x%llx remaining_before=0x%llx elapsed_us=%llu",
                (ULONG)target_pid,
                process_dir_base,
                current_virtual_address,
                physical_address,
                (UINT64)transfer_size,
                is_write ? 1u : 0u,
                (ULONG)operation_status,
                (UINT64)bytes_transferred,
                (UINT64)total_bytes_transferred,
                (UINT64)remaining_size,
                mem_guard::elapsed_us(start, freq));
            if (NT_SUCCESS(operation_status) && bytes_transferred > 0) {
                if (!is_write) {
                    __try {
                        strong::kmemcpy(current_buffer, km_staging, bytes_transferred);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        final_status = (NTSTATUS)GetExceptionCode();
                        break;
                    }
                }
                total_bytes_transferred += bytes_transferred;
                remaining_size -= bytes_transferred;
                current_offset += bytes_transferred;
                final_status = STATUS_SUCCESS;
                continue;
            }
        }
        else {
            WW_LOG("PHYS_RW_TRANSLATE_FAIL pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u total=0x%llx remaining=0x%llx walk_present=%u walk_level=%lu walk_pa=0x%llx elapsed_us=%llu",
                (ULONG)target_pid,
                process_dir_base,
                current_virtual_address,
                (UINT64)transfer_size,
                is_write ? 1u : 0u,
                (UINT64)total_bytes_transferred,
                (UINT64)remaining_size,
                walk.present ? 1u : 0u,
                (ULONG)walk.level,
                walk.physical,
                mem_guard::elapsed_us(start, freq));

        }

        if (softfault_eligible &&
            mem_guard::is_valid_user_range(current_virtual_address) &&
            mem_guard::is_valid_user_range(current_virtual_address + transfer_size - 1))
        {
            if (!proc_lookup_attempted) {
                proc_lookup_attempted = TRUE;
                NTSTATUS lookup_status = _PsLookupProcessByProcessId
                    ? _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)target_pid, &target_proc)
                    : STATUS_NOT_SUPPORTED;
                WW_LOG("PHYS_RW_SOFTFAULT_LOOKUP pid=%lu status=0x%08X process=%p va=0x%llx elapsed_us=%llu",
                    (ULONG)target_pid,
                    (ULONG)lookup_status,
                    target_proc,
                    current_virtual_address,
                    mem_guard::elapsed_us(start, freq));
                if (!NT_SUCCESS(lookup_status)) {
                    target_proc = nullptr;
                }
            }

            if (target_proc) {
                if (!km_staging) {
                    km_staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x1000, 'sFwW');
                }

                if (km_staging) {
                    KAPC_STATE local_apc{};
                    BOOLEAN read_ok = FALSE;
                    SIZE_T bytes_staged = 0;

                    if (_KeStackAttachProcess) { _KeStackAttachProcess(target_proc, &local_apc); }

                    __try {
                        ProbeForRead((PVOID)current_virtual_address, transfer_size, 1);
                        strong::kmemcpy(km_staging, (PVOID)current_virtual_address, transfer_size);
                        bytes_staged = transfer_size;
                        read_ok = TRUE;
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        read_ok = FALSE;
                    }

                    if (_KeUnstackDetachProcess) { _KeUnstackDetachProcess(&local_apc); }

                    if (read_ok && bytes_staged > 0) {
                        __try {
                            strong::kmemcpy(
                                (PVOID)((ULONG_PTR)request->buffer + current_offset),
                                km_staging,
                                bytes_staged
                            );

                            total_bytes_transferred += bytes_staged;
                            remaining_size -= bytes_staged;
                            current_offset += bytes_staged;
                            chunk_done = TRUE;
                            final_status = STATUS_SUCCESS;
                            WW_LOG("PHYS_RW_SOFTFAULT_CHUNK pid=%lu va=0x%llx requested=0x%llx bytes=0x%llx total=0x%llx elapsed_us=%llu",
                                (ULONG)target_pid,
                                current_virtual_address,
                                (UINT64)transfer_size,
                                (UINT64)bytes_staged,
                                (UINT64)total_bytes_transferred,
                                mem_guard::elapsed_us(start, freq));
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            chunk_done = FALSE;
                        }
                    }
                }
            }
        }

        if (chunk_done) {
            if ((total_bytes_transferred & 0x3FFF) == 0) {
                mem_guard::timing_scatter();
            }
            continue;
        }


        if (is_write) {
            final_status = STATUS_UNSUCCESSFUL;
            WW_LOG("PHYS_RW_WRITE_FAIL_CLOSED pid=%lu dtb=0x%llx va=0x%llx requested=0x%llx total=0x%llx remaining=0x%llx elapsed_us=%llu",
                (ULONG)target_pid,
                process_dir_base,
                current_virtual_address,
                (UINT64)transfer_size,
                (UINT64)total_bytes_transferred,
                (UINT64)remaining_size,
                mem_guard::elapsed_us(start, freq));
            break;
        }

        __try {
            strong::kmemset(km_staging, 0, transfer_size);
            __try {
                strong::kmemcpy(current_buffer, km_staging, transfer_size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                final_status = (NTSTATUS)GetExceptionCode();
                break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        WW_LOG("PHYS_RW_READ_ZERO_FILL pid=%lu dtb=0x%llx va=0x%llx requested=0x%llx total_before=0x%llx remaining_before=0x%llx elapsed_us=%llu",
            (ULONG)target_pid,
            process_dir_base,
            current_virtual_address,
            (UINT64)transfer_size,
            (UINT64)total_bytes_transferred,
            (UINT64)remaining_size,
            mem_guard::elapsed_us(start, freq));
        total_bytes_transferred += transfer_size;
        remaining_size -= transfer_size;
        current_offset += transfer_size;
        final_status = STATUS_SUCCESS;

        if ((total_bytes_transferred & 0x3FFF) == 0) {
            mem_guard::timing_scatter();
        }
    }

    if (km_staging) {
        ExFreePoolWithTag(km_staging, 'sFwW');
    }
    if (target_proc) {
        if (_ObfDereferenceObject) { _ObfDereferenceObject(target_proc); }
    }

    request->retSize = total_bytes_transferred;

    if (total_bytes_transferred == 0) {
        final_status = STATUS_UNSUCCESSFUL;
    }
    WW_LOG("PHYS_RW_EXIT pid=%lu dtb=0x%llx va=0x%llx size=0x%llx should_write=%u status=0x%08X ret=0x%llx remaining=0x%llx elapsed_us=%llu",
        (ULONG)target_pid,
        process_dir_base,
        target_addr,
        (UINT64)request->size,
        is_write ? 1u : 0u,
        (ULONG)final_status,
        (UINT64)total_bytes_transferred,
        (UINT64)remaining_size,
        mem_guard::elapsed_us(start, freq));
    return final_status;
}
