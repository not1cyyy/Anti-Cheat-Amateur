#pragma once
/*
 * dbvm_shim.h — DBVM I/O Shim for MemRE
 *
 * Intercepts ReadProcessMemory, WriteProcessMemory, VirtualQueryEx,
 * and VirtualProtectEx when the process handle is the DBVM sentinel.
 * Routes all memory access through DBVM hypervisor hypercalls.
 *
 * MUST be included AFTER <windows.h> and BEFORE any code that uses
 * the intercepted APIs.
 *
 * Architecture:
 *   MemRE scan loop → VirtualQueryEx(sentinel, ...) → page-table walk via DBVM
 *                   → ReadProcessMemory(sentinel, ...) → dbvm_read_process_memory()
 */

#include <cstdint>
#include <cstring>

/* ─── DBVM API (C linkage) ─────────────────────────────────────────────── */
extern "C" {
#include "../DBVM-RW/dbvm.h"
}

/* ─── Sentinel Handle ──────────────────────────────────────────────────── */
/* A deliberately invalid HANDLE value that MemRE stores in g_hTargetProcess
 * when attached via DBVM.  Must never be passed to real Win32 APIs. */
#define DBVM_SENTINEL_HANDLE ((HANDLE)(LONG_PTR)-42)

/* ─── DBVM Shim Global State ──────────────────────────────────────────── */
namespace dbvm_shim {
    inline uint64_t g_cr3         = 0;
    inline uint64_t g_module_base = 0;
    inline bool     g_active      = false;
    inline DWORD    g_pid         = 0;
    inline wchar_t  g_proc_name[MAX_PATH] = {};

    /* CR3 logging buffer — must be page-aligned, exactly 4096 bytes */
    inline __declspec(align(4096)) uint64_t g_cr3_buf[512] = {};
}

/* ─── Save original Win32 function pointers ────────────────────────────── */
namespace dbvm_orig {
    inline auto pReadProcessMemory   = ::ReadProcessMemory;
    inline auto pWriteProcessMemory  = ::WriteProcessMemory;
    inline auto pVirtualQueryEx      = ::VirtualQueryEx;
    inline auto pVirtualProtectEx    = ::VirtualProtectEx;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CR3 Resolution (ported from DBVM-RW/main.c)
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace dbvm_shim {

/* Collect CR3 values from DBVM for a given sleep window. */
inline uint32_t collect_cr3s(int sleep_ms) {
    memset(g_cr3_buf, 0, sizeof(g_cr3_buf));

    BOOL locked = VirtualLock(g_cr3_buf, sizeof(g_cr3_buf));
    if (!locked) {
        SIZE_T wsMin = 0, wsMax = 0;
        GetProcessWorkingSetSize(GetCurrentProcess(), &wsMin, &wsMax);
        SetProcessWorkingSetSize(GetCurrentProcess(),
                                 wsMin + 0x10000, wsMax + 0x10000);
        locked = VirtualLock(g_cr3_buf, sizeof(g_cr3_buf));
    }

    dbvm_log_cr3_start();
    Sleep(sleep_ms);

    uint32_t count = 0;
    dbvm_log_cr3_stop(g_cr3_buf, 512, &count);
    if (locked) VirtualUnlock(g_cr3_buf, sizeof(g_cr3_buf));

    return count;
}

/* Get PEB address via NtQueryInformationProcess (PROCESS_QUERY_INFORMATION).
 * This is NOT blocked by ACE — only VM_READ handles are. */
inline uint64_t get_peb_address(DWORD pid) {
    typedef NTSTATUS (WINAPI *PFN_NQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PFN_NQIP NtQIP = (PFN_NQIP)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return 0;

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;

    struct { PVOID r0; PVOID PebBaseAddress; PVOID r1[4]; } pbi;
    memset(&pbi, 0, sizeof(pbi));
    ULONG returned = 0;
    NTSTATUS st = NtQIP(h, 0, &pbi, sizeof(pbi), &returned);
    CloseHandle(h);
    return (st == 0) ? (uint64_t)(uintptr_t)pbi.PebBaseAddress : 0;
}

/* Get module base via ToolHelp (no OpenProcess needed). */
inline uint64_t get_module_base_toolhelp(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    uint64_t base = 0;
    if (Module32FirstW(snap, &me)) {
        base = (uint64_t)(uintptr_t)me.modBaseAddr;
    }
    CloseHandle(snap);
    return base;
}

/* Get process name via ToolHelp. */
inline bool get_proc_name(DWORD pid, wchar_t* out, size_t sz) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcsncpy_s(out, sz, pe.szExeFile, _TRUNCATE);
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* Resolve CR3 via known module base (Tier 1: MZ probe at module VA). */
inline int resolve_cr3_modbase(DWORD pid, uint64_t module_base, uint64_t* cr3_out) {
    if (module_base == 0) return -1;
    static const int sleep_ms[] = { 500, 1000, 2000 };

    for (int attempt = 0; attempt < 3; attempt++) {
        uint32_t count = collect_cr3s(sleep_ms[attempt]);
        if (count == 0) continue;

        for (uint32_t i = 0; i < count && i < 512; i++) {
            uint64_t cr3 = g_cr3_buf[i];
            if (!cr3 || (cr3 & 0xFFF)) continue;
            uint64_t pa = 0;
            if (dbvm_va_to_pa_ex(module_base, cr3, &pa) != 0) continue;
            uint16_t sig = 0;
            if (dbvm_read_physical(pa, &sig, 2) != 0) continue;
            if (sig == 0x5A4D) { *cr3_out = cr3; return 0; }
        }
    }
    return -1;
}

/* Resolve CR3 via PEB path (Tier 2: EAC-compatible — NtQIP for PEB, DBVM for reads). */
inline int resolve_cr3_peb(DWORD pid, uint64_t peb_va,
                            uint64_t* cr3_out, uint64_t* base_out) {
    if (peb_va == 0) return -1;
    static const int sleep_ms[] = { 500, 1000, 2000 };

    for (int attempt = 0; attempt < 3; attempt++) {
        uint32_t count = collect_cr3s(sleep_ms[attempt]);
        if (count == 0) continue;

        for (uint32_t i = 0; i < count && i < 512; i++) {
            uint64_t cr3 = g_cr3_buf[i];
            if (!cr3 || (cr3 & 0xFFF)) continue;

            uint64_t peb_pa = 0;
            if (dbvm_va_to_pa_ex(peb_va, cr3, &peb_pa) != 0) continue;

            uint64_t img_base = 0;
            if (dbvm_read_physical(peb_pa + 0x10, &img_base, 8) != 0) continue;
            if (img_base == 0 || (img_base & 0xFFF)) continue;

            uint64_t img_pa = 0;
            uint16_t sig = 0;
            if (dbvm_va_to_pa_ex(img_base, cr3, &img_pa) != 0) continue;
            if (dbvm_read_physical(img_pa, &sig, 2) != 0) continue;

            if (sig == 0x5A4D) {
                *cr3_out  = cr3;
                *base_out = img_base;
                return 0;
            }
        }
    }
    return -1;
}

/* Full three-tier CR3 resolution. Returns true on success. */
inline bool resolve_cr3_full(DWORD pid) {
    g_pid = pid;
    g_cr3 = 0;
    g_module_base = 0;
    get_proc_name(pid, g_proc_name, _countof(g_proc_name));

    /* Tier 1: ToolHelp module base → MZ probe */
    uint64_t base = get_module_base_toolhelp(pid);
    uint64_t cr3 = 0;

    if (base != 0) {
        if (resolve_cr3_modbase(pid, base, &cr3) == 0) {
            g_cr3 = cr3;
            g_module_base = base;
            g_active = true;
            return true;
        }
    }

    /* Tier 2: PEB path (EAC-compatible) */
    uint64_t peb = get_peb_address(pid);
    if (peb != 0) {
        if (resolve_cr3_peb(pid, peb, &cr3, &base) == 0) {
            g_cr3 = cr3;
            g_module_base = base;
            g_active = true;
            return true;
        }
    }

    return false;
}

} // namespace dbvm_shim


/* ═══════════════════════════════════════════════════════════════════════════
 * VirtualQueryEx — Kernel Driver Region Cache (GothGirlFeet)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Uses the GothGirlFeet kernel driver (GothGirlFeet.sys) for region
 * enumeration instead of walking page tables via DBVM.
 *
 * The driver uses KeStackAttachProcess + ZwQueryVirtualMemory which is
 * native kernel speed — zero VMCALLs, microsecond latency.
 *
 * The cached region list is populated on first VirtualQueryEx call and
 * invalidated on detach or re-attach.
 *
 * Never returns RegionSize=0 (would cause infinite loop in MemRE).
 */

#include <vector>
#include "../mre_drv/ggf_shared.h"

namespace ggf_driver {

    /* Handle to the GothGirlFeet kernel driver */
    inline HANDLE g_device = INVALID_HANDLE_VALUE;

    /* Cached region list from the driver */
    struct Region {
        uint64_t start;
        uint64_t size;
    };
    inline std::vector<Region> g_regions;
    inline bool                g_cache_valid = false;

    /* Connect to the hooked null device and verify driver is loaded */
    inline bool connect() {
        if (g_device != INVALID_HANDLE_VALUE) return true;

        /* \\.\NUL always exists — we talk to our hook on \Driver\Null */
        g_device = CreateFileW(
            GGF_USER_PATH,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (g_device == INVALID_HANDLE_VALUE)
            return false;

        /* Ping the hook to verify GothGirlFeet.sys is mapped */
        ULONG magic = 0;
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(
            g_device, IOCTL_GGF_PING,
            NULL, 0,
            &magic, sizeof(magic),
            &ret, NULL);

        if (!ok || ret != sizeof(ULONG) || magic != GGF_PING_MAGIC) {
            /* Hook not active — driver not mapped yet */
            CloseHandle(g_device);
            g_device = INVALID_HANDLE_VALUE;
            return false;
        }

        return true;
    }

    /* Disconnect (just close the NUL handle; hook persists until reboot) */
    inline void disconnect() {
        if (g_device != INVALID_HANDLE_VALUE) {
            CloseHandle(g_device);
            g_device = INVALID_HANDLE_VALUE;
        }
        g_cache_valid = false;
        g_regions.clear();
    }

    /* Query the driver for all committed regions of a process.
     * Populates g_regions with the result. */
    inline void enum_regions(DWORD pid) {
        g_regions.clear();
        g_cache_valid = false;

        if (g_device == INVALID_HANDLE_VALUE) {
            /* Driver not loaded — show error once */
            static bool warned = false;
            if (!warned) {
                warned = true;
                MessageBoxW(NULL,
                    L"GothGirlFeet.sys not mapped!\n\n"
                    L"Run kdmapper.exe GothGirlFeet.sys first.",
                    L"Driver Required", MB_ICONERROR | MB_OK);
            }
            return;
        }

        /* Prepare IOCTL call */
        GGF_INPUT input = {};
        input.pid = pid;

        /* Allocate output buffer on heap (~256KB) */
        const size_t outSize = GGF_REGIONS_OUTBUF_SIZE;
        std::vector<BYTE> outBuf(outSize, 0);
        DWORD returned = 0;

        BOOL ok = DeviceIoControl(
            g_device,
            IOCTL_GGF_ENUM_REGIONS,
            &input, sizeof(input),
            outBuf.data(), (DWORD)outSize,
            &returned, NULL);

        if (!ok || returned < sizeof(unsigned long) * 2)
            return;

        /* Parse output */
        auto* out = reinterpret_cast<GGF_ENUM_REGIONS_OUT*>(outBuf.data());
        unsigned long count = out->count;

        g_regions.reserve(count);
        for (unsigned long i = 0; i < count; i++) {
            g_regions.push_back({ out->regions[i].base, out->regions[i].size });
        }

        g_cache_valid = true;
    }

    /* Invalidate cache (call on detach or re-attach) */
    inline void invalidate() {
        g_cache_valid = false;
        g_regions.clear();
    }

    /* Ensure cache is populated for the current target PID */
    inline void ensure_cache() {
        if (g_cache_valid) return;
        enum_regions(dbvm_shim::g_pid);
    }

    /*
     * Find the region containing or immediately after 'va'.
     * Returns index into g_regions, or g_regions.size() if past all regions.
     */
    inline size_t find_region_at_or_after(uint64_t va) {
        /* Binary search: find first region where start+size > va */
        size_t lo = 0, hi = g_regions.size();
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (g_regions[mid].start + g_regions[mid].size <= va)
                lo = mid + 1;
            else
                hi = mid;
        }
        return lo;
    }

} /* namespace ggf_driver */


inline SIZE_T DBVM_VirtualQueryEx(
    HANDLE hProcess,
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength)
{
    if (hProcess != DBVM_SENTINEL_HANDLE) {
        return dbvm_orig::pVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
    }

    /* Ensure the region cache is built */
    ggf_driver::ensure_cache();

    memset(lpBuffer, 0, sizeof(MEMORY_BASIC_INFORMATION));
    uint64_t va = (uint64_t)(uintptr_t)lpAddress;
    uint64_t page_va = va & ~0xFFFULL;

    static constexpr uint64_t USER_LIMIT = 0x7FFFFFFFE000ULL;
    if (page_va >= USER_LIMIT) {
        /* Past userspace — report as free to end scanning */
        lpBuffer->BaseAddress = (PVOID)page_va;
        lpBuffer->RegionSize = 0x1000;
        lpBuffer->State = MEM_FREE;
        lpBuffer->Protect = PAGE_NOACCESS;
        return sizeof(MEMORY_BASIC_INFORMATION);
    }

    auto& regions = ggf_driver::g_regions;
    size_t idx = ggf_driver::find_region_at_or_after(page_va);

    /* Maximum region size to report — keeps RPM buffers small and
     * prevents allocating hundreds of MB per scan chunk. 4MB is a
     * sweet spot: large enough for efficient scanning, small enough
     * to keep memory usage reasonable with DBVM's per-page reads. */
    static constexpr SIZE_T MAX_REGION_REPORT = 4ULL * 1024 * 1024;  /* 4 MB */

    if (idx < regions.size()) {
        auto& r = regions[idx];

        if (page_va >= r.start && page_va < r.start + r.size) {
            /* VA is inside a committed region.
             * Report from page_va with capped size so MemRE sees
             * manageable chunks and will call back for the rest. */
            uint64_t remainder_in_region = (r.start + r.size) - page_va;
            SIZE_T report_size = (SIZE_T)(remainder_in_region < MAX_REGION_REPORT
                                          ? remainder_in_region : MAX_REGION_REPORT);
            lpBuffer->BaseAddress = (PVOID)page_va;
            lpBuffer->AllocationBase = (PVOID)r.start;
            lpBuffer->AllocationProtect = PAGE_READWRITE;
            lpBuffer->RegionSize = report_size;
            lpBuffer->State = MEM_COMMIT;
            lpBuffer->Protect = PAGE_READWRITE;
            lpBuffer->Type = MEM_PRIVATE;
            return sizeof(MEMORY_BASIC_INFORMATION);
        }

        /* VA is in the free gap before this region */
        lpBuffer->BaseAddress = (PVOID)page_va;
        lpBuffer->AllocationBase = NULL;
        lpBuffer->AllocationProtect = 0;
        lpBuffer->RegionSize = (SIZE_T)(r.start - page_va);
        lpBuffer->State = MEM_FREE;
        lpBuffer->Protect = PAGE_NOACCESS;
        lpBuffer->Type = 0;

        /* Safety: never return 0 */
        if (lpBuffer->RegionSize == 0)
            lpBuffer->RegionSize = 0x1000;

        return sizeof(MEMORY_BASIC_INFORMATION);
    }

    /* Past all known regions → free to end of userspace */
    lpBuffer->BaseAddress = (PVOID)page_va;
    lpBuffer->AllocationBase = NULL;
    lpBuffer->AllocationProtect = 0;
    uint64_t remaining = USER_LIMIT - page_va;
    lpBuffer->RegionSize = (SIZE_T)(remaining > 0 ? remaining : 0x1000);
    lpBuffer->State = MEM_FREE;
    lpBuffer->Protect = PAGE_NOACCESS;
    lpBuffer->Type = 0;

    /* Safety: never return 0 */
    if (lpBuffer->RegionSize == 0)
        lpBuffer->RegionSize = 0x1000;

    return sizeof(MEMORY_BASIC_INFORMATION);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * ReadProcessMemory Shim — Optimized Batch Physical Read
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Key optimization: Instead of calling dbvm_read_process_memory() which
 * does a full 4-level page table walk (4 VMCALLs) PLUS a physical read
 * (1 VMCALL) = 5 VMCALLs per 4KB page, we exploit page-table locality:
 *
 *   1. Read the relevant PT (page table) level once (1 VMCALL for 4KB
 *      = 512 entries covering 2MB of VA space).
 *   2. For each page in that PT, extract the PA from the cached entry
 *      and do a single dbvm_read_physical (1 VMCALL per page).
 *
 * This reduces from ~5 VMCALLs/page to ~1.002 VMCALLs/page for
 * sequential reads within a 2MB PT range (the common case in scans).
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace dbvm_rpm_opt {

    /* Page table entry constants (same as dbvm_regions, but keep local) */
    static constexpr uint64_t PRESENT    = 1ULL;
    static constexpr uint64_t LARGE_PAGE = (1ULL << 7);
    static constexpr uint64_t ADDR_MASK  = 0x000FFFFFFFFFF000ULL;

    /*
     * Read a contiguous VA range from the target process, one page at a time,
     * but batch the PT walk by reading entire PT levels in bulk.
     *
     * Returns: number of bytes successfully read (partial reads OK).
     */
    inline SIZE_T fast_read(uint64_t cr3, uint64_t start_va, void* buf, SIZE_T size)
    {
        uint8_t* dst = (uint8_t*)buf;
        SIZE_T total_read = 0;
        uint64_t va = start_va;
        SIZE_T remaining = size;

        /* Mask CR3 to physical base */
        uint64_t cr3_pa = cr3 & ADDR_MASK;

        /* Cache for the current Page Table (512 entries covering 2MB).
         * We cache which 2MB-aligned VA range it covers to avoid re-reading. */
        uint64_t cached_pt[512];
        uint64_t cached_pt_va_base = ~0ULL;  /* which 2MB region is cached */
        bool     cached_pt_valid = false;

        /* Also cache the PD entry for the current 1GB PDPT range */
        uint64_t cached_pd[512];
        uint64_t cached_pd_va_base = ~0ULL;  /* which 1GB region */
        bool     cached_pd_valid = false;

        while (remaining > 0) {
            uint64_t page_va = va & ~0xFFFULL;
            uint64_t page_offset = va & 0xFFF;
            uint32_t chunk = (uint32_t)(0x1000 - page_offset);
            if (chunk > remaining) chunk = (uint32_t)remaining;

            /* Resolve this VA to a physical address using cached PT data */
            uint64_t pa = 0;
            bool resolved = false;

            /* Extract page table indices */
            int pml4i = (int)((va >> 39) & 0x1FF);
            int pdpti = (int)((va >> 30) & 0x1FF);
            int pdi   = (int)((va >> 21) & 0x1FF);
            int pti   = (int)((va >> 12) & 0x1FF);

            /* 2MB-aligned base for PT cache lookup */
            uint64_t va_2mb_base = va & ~((1ULL << 21) - 1);

            /* Check if we need to refresh the PD cache (1GB alignment) */
            uint64_t va_1gb_base = va & ~((1ULL << 30) - 1);
            if (!cached_pd_valid || cached_pd_va_base != va_1gb_base) {
                /* Walk PML4 → PDPT → PD (3 VMCALLs) */
                uint64_t pml4e = 0;
                if (dbvm_read_physical(cr3_pa + (uint64_t)pml4i * 8, &pml4e, 8) != 0 || !(pml4e & PRESENT))
                    break;

                uint64_t pdpte = 0;
                uint64_t pdpt_pa = pml4e & ADDR_MASK;
                if (dbvm_read_physical(pdpt_pa + (uint64_t)pdpti * 8, &pdpte, 8) != 0 || !(pdpte & PRESENT))
                    break;

                /* Check for 1GB large page */
                if (pdpte & LARGE_PAGE) {
                    pa = (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
                    resolved = true;
                    cached_pd_valid = false;  /* no PD level for large pages */
                    cached_pt_valid = false;
                } else {
                    /* Read entire PD table (512 entries) in one VMCALL */
                    uint64_t pd_pa = pdpte & ADDR_MASK;
                    if (dbvm_read_physical(pd_pa, cached_pd, sizeof(cached_pd)) != 0)
                        break;
                    cached_pd_va_base = va_1gb_base;
                    cached_pd_valid = true;
                    cached_pt_valid = false;  /* PD changed, invalidate PT cache */
                }
            }

            if (!resolved && cached_pd_valid) {
                uint64_t pde = cached_pd[pdi];
                if (!(pde & PRESENT))
                    break;

                /* Check for 2MB large page */
                if (pde & LARGE_PAGE) {
                    pa = (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
                    resolved = true;
                } else {
                    /* Do we have the PT cached for this 2MB range? */
                    if (!cached_pt_valid || cached_pt_va_base != va_2mb_base) {
                        /* Read entire PT (512 entries) in one VMCALL */
                        uint64_t pt_pa = pde & ADDR_MASK;
                        if (dbvm_read_physical(pt_pa, cached_pt, sizeof(cached_pt)) != 0)
                            break;
                        cached_pt_va_base = va_2mb_base;
                        cached_pt_valid = true;
                    }

                    uint64_t pte = cached_pt[pti];
                    if (!(pte & PRESENT))
                        break;

                    pa = (pte & ADDR_MASK) | page_offset;
                    resolved = true;
                }
            }

            if (!resolved)
                break;

            /* Physical read — 1 VMCALL */
            if (dbvm_read_physical(pa, dst, chunk) != 0)
                break;

            dst += chunk;
            va += chunk;
            remaining -= chunk;
            total_read += chunk;
        }

        return total_read;
    }

} /* namespace dbvm_rpm_opt */


inline BOOL DBVM_ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead)
{
    if (hProcess != DBVM_SENTINEL_HANDLE) {
        return dbvm_orig::pReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    /* ── Fast path: kernel direct read via IOCTL_GGF_READ_MEMORY ──────────
     * The driver does KeStackAttachProcess + MmCopyMemory — same mechanism
     * Windows uses internally for ReadProcessMemory, no VMCALL overhead.
     * Loops for reads larger than GGF_READ_MAX_SIZE (4MB chunks). */
    if (ggf_driver::g_device != INVALID_HANDLE_VALUE) {
        uint8_t* dst   = (uint8_t*)lpBuffer;
        uint64_t va    = (uint64_t)(uintptr_t)lpBaseAddress;
        SIZE_T   remaining = nSize;
        SIZE_T   total_read = 0;
        bool     all_ok    = true;

        while (remaining > 0) {
            ULONG chunk = (ULONG)(remaining < (SIZE_T)GGF_READ_MAX_SIZE
                                  ? remaining : (SIZE_T)GGF_READ_MAX_SIZE);

            GGF_READ_INPUT inp;
            inp.pid   = dbvm_shim::g_pid;
            inp._pad  = 0;
            inp.va    = va;
            inp.size  = chunk;
            inp._pad2 = 0;

            DWORD returned = 0;
            BOOL ok = DeviceIoControl(
                ggf_driver::g_device,
                IOCTL_GGF_READ_MEMORY,
                &inp, sizeof(inp),
                dst, chunk,
                &returned, NULL);

            if (!ok || returned == 0) {
                all_ok = false;
                break;
            }

            dst        += returned;
            va         += returned;
            total_read += returned;
            remaining  -= returned;
        }

        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = total_read;

        /* If we got any data, report success even for partial reads */
        if (total_read > 0) return TRUE;

        /* Kernel path failed entirely — fall through to VMCALL */
        (void)all_ok;
    }

    /* ── Fallback: VMCALL page-table walk (when driver not loaded / failed) */
    SIZE_T bytesRead = dbvm_rpm_opt::fast_read(
        dbvm_shim::g_cr3,
        (uint64_t)(uintptr_t)lpBaseAddress,
        lpBuffer,
        nSize);

    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = bytesRead;

    /* Return TRUE even for partial reads — scan engine checks bytesRead */
    return (bytesRead > 0) ? TRUE : FALSE;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * WriteProcessMemory Shim
 * ═══════════════════════════════════════════════════════════════════════════ */

inline BOOL DBVM_WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten)
{
    if (hProcess != DBVM_SENTINEL_HANDLE) {
        return dbvm_orig::pWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    uint64_t va = (uint64_t)(uintptr_t)lpBaseAddress;
    int rc = dbvm_write_process_memory(dbvm_shim::g_cr3, va, lpBuffer, (uint32_t)nSize);
    if (rc == 0) {
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = nSize;
        return TRUE;
    }
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
    return FALSE;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * VirtualProtectEx Shim — no-op when DBVM (hypervisor bypasses protection)
 * ═══════════════════════════════════════════════════════════════════════════ */

inline BOOL DBVM_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect)
{
    if (hProcess != DBVM_SENTINEL_HANDLE) {
        return dbvm_orig::pVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    /* DBVM operates at physical level — protection bits are irrelevant */
    if (lpflOldProtect) *lpflOldProtect = PAGE_EXECUTE_READWRITE;
    return TRUE;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Macro Redirection
 *
 * These macros redirect all subsequent uses of the Win32 APIs to our shims.
 * The shim functions dispatch based on the handle value:
 *   - DBVM_SENTINEL_HANDLE → DBVM path
 *   - Anything else → real Win32 API (for self-reads, etc.)
 * ═══════════════════════════════════════════════════════════════════════════ */

#define ReadProcessMemory   DBVM_ReadProcessMemory
#define WriteProcessMemory  DBVM_WriteProcessMemory
#define VirtualQueryEx      DBVM_VirtualQueryEx
#define VirtualProtectEx    DBVM_VirtualProtectEx
