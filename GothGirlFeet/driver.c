/*
 * driver.c — GothGirlFeet Kernel Driver (kdmapper-compatible)
 *
 * Manually mapped via kdmapper. No DriverObject, no IoCreateDevice,
 * no signing. Hooks \Driver\Null's IRP_MJ_DEVICE_CONTROL to communicate
 * with user-mode via DeviceIoControl("\\.\NUL", ...).
 *
 * IOCTLs:
 *   IOCTL_GGF_ENUM_REGIONS  — Enumerate committed memory regions for a PID
 *   IOCTL_GGF_ENUM_MODULES  — Enumerate loaded modules for a PID
 *   IOCTL_GGF_PING          — Verify hook is active (returns GGF_PING_MAGIC)
 */

#include <ntifs.h>
#include <windef.h>
#include "ggf_shared.h"

/* ─── Undocumented ntoskrnl exports ──────────────────────────────────── */

EXTERN_C NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);

EXTERN_C NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object);

EXTERN_C POBJECT_TYPE *IoDriverObjectType;

EXTERN_C NTKERNELAPI NTSTATUS MmCopyMemory(
    PVOID TargetAddress,
    MM_COPY_ADDRESS SourceAddress,
    SIZE_T NumberOfBytes,
    ULONG Flags,
    PSIZE_T NumberOfBytesTransferred);


/* ─── PEB / LDR structures (opaque in WDK headers) ──────────────────── */

typedef struct _GGF_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} GGF_PEB_LDR_DATA, *PGGF_PEB_LDR_DATA;

typedef struct _GGF_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} GGF_LDR_DATA_TABLE_ENTRY, *PGGF_LDR_DATA_TABLE_ENTRY;


/* ─── Globals ────────────────────────────────────────────────────────── */

static PDRIVER_DISPATCH g_OrigDevControl = NULL;


/* ═══════════════════════════════════════════════════════════════════════
 * Region Enumeration
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS GgfEnumRegions(
    ULONG Pid,
    PGGF_ENUM_REGIONS_OUT OutBuf,
    ULONG OutLen,
    PULONG BytesWritten)
{
    PEPROCESS Process = NULL;
    NTSTATUS status;
    KAPC_STATE ApcState;

    *BytesWritten = 0;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(status))
        return status;

    KeStackAttachProcess(Process, &ApcState);

    ULONG count = 0;
    ULONG maxEntries = (OutLen - FIELD_OFFSET(GGF_ENUM_REGIONS_OUT, regions)) / sizeof(GGF_REGION);
    if (maxEntries > GGF_MAX_REGIONS)
        maxEntries = GGF_MAX_REGIONS;

    PVOID addr = (PVOID)(ULONG_PTR)0x10000;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T retLen;

    while (count < maxEntries) {
        status = ZwQueryVirtualMemory(
            NtCurrentProcess(),
            addr,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &retLen);

        if (!NT_SUCCESS(status))
            break;

        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)))
        {
            OutBuf->regions[count].base = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
            OutBuf->regions[count].size = (ULONG64)mbi.RegionSize;
            count++;
        }

        addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR)addr >= 0x7FFFFFFFE000ULL)
            break;
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    OutBuf->count = count;
    OutBuf->_pad = 0;
    *BytesWritten = FIELD_OFFSET(GGF_ENUM_REGIONS_OUT, regions) + count * sizeof(GGF_REGION);

    return STATUS_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 * Module Enumeration (PEB LDR walk)
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS GgfEnumModules(
    ULONG Pid,
    PGGF_ENUM_MODULES_OUT OutBuf,
    ULONG OutLen,
    PULONG BytesWritten)
{
    PEPROCESS Process = NULL;
    NTSTATUS status;
    KAPC_STATE ApcState;

    *BytesWritten = 0;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(status))
        return status;

    PPEB peb = PsGetProcessPeb(Process);
    if (!peb) {
        ObDereferenceObject(Process);
        return STATUS_UNSUCCESSFUL;
    }

    KeStackAttachProcess(Process, &ApcState);

    ULONG count = 0;
    ULONG maxEntries = (OutLen - FIELD_OFFSET(GGF_ENUM_MODULES_OUT, modules)) / sizeof(GGF_MODULE);
    if (maxEntries > GGF_MAX_MODULES)
        maxEntries = GGF_MAX_MODULES;

    __try {
        /* PEB is opaque in WDK. On x64, PEB.Ldr is at offset 0x18 */
        PGGF_PEB_LDR_DATA ldr = *(PGGF_PEB_LDR_DATA*)((UCHAR*)peb + 0x18);
        if (ldr) {
            PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
            PLIST_ENTRY entry = head->Flink;

            while (entry != head && count < maxEntries) {
                PGGF_LDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(
                    entry, GGF_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

                OutBuf->modules[count].base = (ULONG64)(ULONG_PTR)mod->DllBase;
                OutBuf->modules[count].size = (ULONG64)mod->SizeOfImage;

                ULONG nameLen = mod->BaseDllName.Length / sizeof(WCHAR);
                if (nameLen >= GGF_MODULE_NAME_LEN)
                    nameLen = GGF_MODULE_NAME_LEN - 1;

                if (mod->BaseDllName.Buffer && nameLen > 0)
                    RtlCopyMemory(OutBuf->modules[count].name,
                                  mod->BaseDllName.Buffer,
                                  nameLen * sizeof(WCHAR));
                OutBuf->modules[count].name[nameLen] = L'\0';

                count++;
                entry = entry->Flink;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* PEB read failed — target may be exiting */
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    OutBuf->count = count;
    OutBuf->_pad = 0;
    *BytesWritten = FIELD_OFFSET(GGF_ENUM_MODULES_OUT, modules) + count * sizeof(GGF_MODULE);

    return STATUS_SUCCESS;
}


/* ═══════════════════════════════════════════════════════════════════════
 * Direct Memory Read (kernel-speed, no VMCALL)
 *
 * Attaches to the target process, then calls MmCopyMemory with
 * MM_COPY_MEMORY_VIRTUAL to read its virtual address space directly.
 * This is equivalent to what the kernel does for ReadProcessMemory.
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS GgfReadMemory(
    ULONG     Pid,
    ULONG64   Va,
    ULONG     Size,
    PVOID     OutBuf,
    PULONG    BytesWritten)
{
    PEPROCESS Process = NULL;
    NTSTATUS  status;
    KAPC_STATE ApcState;
    SIZE_T    copied = 0;

    *BytesWritten = 0;

    if (Size == 0 || OutBuf == NULL)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(status))
        return status;

    KeStackAttachProcess(Process, &ApcState);

    __try {
        MM_COPY_ADDRESS src;
        src.VirtualAddress = (PVOID)(ULONG_PTR)Va;
        status = MmCopyMemory(OutBuf, src, (SIZE_T)Size,
                              MM_COPY_MEMORY_VIRTUAL, &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0;
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    *BytesWritten = (ULONG)copied;
    return status;
}


/* ═══════════════════════════════════════════════════════════════════════
 * Direct Memory Write (kernel-speed)
 *
 * Attaches to the target process and writes to its virtual address space
 * using MmCopyMemory with MM_COPY_MEMORY_VIRTUAL.
 * The data buffer immediately follows the GGF_WRITE_INPUT header.
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS GgfWriteMemory(
    ULONG     Pid,
    ULONG64   Va,
    PVOID     SrcBuf,   /* kernel-mode source buffer */
    ULONG     Size)
{
    PEPROCESS Process = NULL;
    NTSTATUS  status;
    KAPC_STATE ApcState;

    if (Size == 0 || SrcBuf == NULL)
        return STATUS_INVALID_PARAMETER;
    if (Size > GGF_READ_MAX_SIZE)
        return STATUS_INVALID_BUFFER_SIZE;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(status))
        return status;

    KeStackAttachProcess(Process, &ApcState);

    __try {
        /*
         * MmCopyMemory cannot write to user-mode VA — it is read-only.
         * Use ProbeForWrite + RtlCopyMemory under SEH instead.
         * ProbeForWrite validates the range; the SEH catches protection faults.
         */
        ProbeForWrite((PVOID)(ULONG_PTR)Va, Size, 1);
        RtlCopyMemory((PVOID)(ULONG_PTR)Va, SrcBuf, Size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);

    return status;
}


/* ═══════════════════════════════════════════════════════════════════════
 * Hooked IRP_MJ_DEVICE_CONTROL on \Driver\Null
 * ═══════════════════════════════════════════════════════════════════════ */

static NTSTATUS NTAPI HookedDevControl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;

    /* Quick reject — not one of our magic IOCTLs → original handler */
    if (code != IOCTL_GGF_ENUM_REGIONS &&
        code != IOCTL_GGF_ENUM_MODULES &&
        code != IOCTL_GGF_PING         &&
        code != IOCTL_GGF_READ_MEMORY  &&
        code != IOCTL_GGF_WRITE_MEMORY)
    {
        return g_OrigDevControl(DevObj, Irp);
    }

    /* ── Our request ── */
    ULONG inLen   = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen  = sp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf     = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG written = 0;

    /* ── PING: return magic to confirm hook is alive ── */
    if (code == IOCTL_GGF_PING) {
        if (outLen >= sizeof(ULONG) && buf) {
            *(ULONG*)buf = GGF_PING_MAGIC;
            written = sizeof(ULONG);
        }
        goto done;
    }

    /* ── ENUM_REGIONS / ENUM_MODULES ── */
    if (!buf || inLen < sizeof(GGF_INPUT)) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    {
        ULONG pid = ((PGGF_INPUT)buf)->pid;

        if (code == IOCTL_GGF_ENUM_REGIONS) {
            if (outLen < FIELD_OFFSET(GGF_ENUM_REGIONS_OUT, regions)) {
                status = STATUS_BUFFER_TOO_SMALL;
            } else {
                status = GgfEnumRegions(pid,
                    (PGGF_ENUM_REGIONS_OUT)buf, outLen, &written);
            }
        }
        else if (code == IOCTL_GGF_ENUM_MODULES) {
            if (outLen < FIELD_OFFSET(GGF_ENUM_MODULES_OUT, modules)) {
                status = STATUS_BUFFER_TOO_SMALL;
            } else {
                status = GgfEnumModules(pid,
                    (PGGF_ENUM_MODULES_OUT)buf, outLen, &written);
            }
        }
        else if (code == IOCTL_GGF_READ_MEMORY) {
            if (inLen < sizeof(GGF_READ_INPUT)) {
                status = STATUS_INVALID_PARAMETER;
            } else {
                /* Copy input params before the output overwrites the buffer */
                GGF_READ_INPUT rdin;
                RtlCopyMemory(&rdin, buf, sizeof(rdin));
                ULONG reqSize = rdin.size;
                if (reqSize > outLen) reqSize = outLen;
                if (reqSize > GGF_READ_MAX_SIZE) reqSize = GGF_READ_MAX_SIZE;
                status = GgfReadMemory(rdin.pid, rdin.va, reqSize,
                                       buf, &written);
            }
        }
        else if (code == IOCTL_GGF_WRITE_MEMORY) {
            /* Input layout: GGF_WRITE_INPUT header + data bytes inline.
             * With METHOD_BUFFERED, inLen = sizeof(header) + dataSize.
             * The data to write sits at buf + sizeof(GGF_WRITE_INPUT). */
            if (inLen < sizeof(GGF_WRITE_INPUT) + 1) {
                status = STATUS_INVALID_PARAMETER;
            } else {
                GGF_WRITE_INPUT wrin;
                RtlCopyMemory(&wrin, buf, sizeof(wrin));
                ULONG dataSize = (ULONG)(inLen - sizeof(GGF_WRITE_INPUT));
                if (wrin.size > dataSize) wrin.size = dataSize;
                if (wrin.size > GGF_READ_MAX_SIZE) wrin.size = GGF_READ_MAX_SIZE;
                PVOID dataBuf = (PUCHAR)buf + sizeof(GGF_WRITE_INPUT);
                status = GgfWriteMemory(wrin.pid, wrin.va, dataBuf, wrin.size);
                written = 0;
            }
        }
    }

done:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = written;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


/* ═══════════════════════════════════════════════════════════════════════
 * DriverEntry — called by kdmapper after manual mapping
 *
 * DriverObject and RegistryPath are NULL (manually mapped, no loader).
 * We hook \Driver\Null's dispatch table to establish comms.
 * ═══════════════════════════════════════════════════════════════════════ */

EXTERN_C NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    /* Find \Driver\Null driver object */
    UNICODE_STRING drvName;
    RtlInitUnicodeString(&drvName, L"\\Driver\\Null");

    PDRIVER_OBJECT nullDrv = NULL;
    NTSTATUS status = ObReferenceObjectByName(
        &drvName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&nullDrv);

    if (!NT_SUCCESS(status))
        return status;

    /* Atomically swap IRP_MJ_DEVICE_CONTROL handler */
    g_OrigDevControl = (PDRIVER_DISPATCH)InterlockedExchangePointer(
        (volatile PVOID*)&nullDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        (PVOID)HookedDevControl);

    ObDereferenceObject(nullDrv);

    return STATUS_SUCCESS;
}
