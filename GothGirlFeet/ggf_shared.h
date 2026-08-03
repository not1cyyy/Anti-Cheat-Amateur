#pragma once
/*
 * ggf_shared.h — Shared IOCTL definitions for GothGirlFeet kernel driver
 *
 * Included by BOTH the kernel driver (.sys) and user-mode app (.exe).
 * Defines IOCTL codes, input/output structures.
 *
 * kdmapper-compatible: Communication happens via hooked \Driver\Null
 * dispatch table. User-mode opens \\.\NUL and sends our magic IOCTLs.
 */

/* ─── Device Path (user-mode opens the null device) ───────────────────── */
#define GGF_USER_PATH       L"\\\\.\\NUL"

/* ─── IOCTL Codes ─────────────────────────────────────────────────────── */
#define GGF_DEVICE_TYPE     0xBEEF

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType)<<16) | ((Access)<<14) | ((Function)<<2) | (Method))
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED     0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS     0
#endif

#define IOCTL_GGF_ENUM_REGIONS  CTL_CODE(GGF_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GGF_ENUM_MODULES  CTL_CODE(GGF_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GGF_PING          CTL_CODE(GGF_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GGF_READ_MEMORY   CTL_CODE(GGF_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GGF_WRITE_MEMORY  CTL_CODE(GGF_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Ping response magic — user-mode checks this to verify hook is alive */
#define GGF_PING_MAGIC      0xDEADC0DE

/* ─── Limits ──────────────────────────────────────────────────────────── */
#define GGF_MAX_REGIONS     16384
#define GGF_MAX_MODULES     512
#define GGF_MODULE_NAME_LEN 256

/* ─── Input Structure (same for ENUM_REGIONS and ENUM_MODULES) ────────── */
typedef struct _GGF_INPUT {
    unsigned long pid;
} GGF_INPUT, *PGGF_INPUT;

/* ─── Input: Memory Read Request ─────────────────────────────────────── */
#define GGF_READ_MAX_SIZE   (4 * 1024 * 1024)   /* 4 MB cap per call */

typedef struct _GGF_READ_INPUT {
    unsigned long     pid;   /* target process ID */
    unsigned long     _pad;  /* alignment */
    unsigned __int64  va;    /* start virtual address to read */
    unsigned long     size;  /* bytes to read (capped at GGF_READ_MAX_SIZE) */
    unsigned long     _pad2; /* keep struct 8-byte aligned */
} GGF_READ_INPUT, *PGGF_READ_INPUT;

/* ─── Input: Memory Write Request ────────────────────────────────────── */
/* Layout: GGF_WRITE_INPUT header immediately followed by 'size' data bytes */
typedef struct _GGF_WRITE_INPUT {
    unsigned long     pid;   /* target process ID */
    unsigned long     _pad;  /* alignment */
    unsigned __int64  va;    /* destination virtual address */
    unsigned long     size;  /* bytes to write */
    unsigned long     _pad2; /* keep struct 8-byte aligned */
    /* data bytes follow inline */
} GGF_WRITE_INPUT, *PGGF_WRITE_INPUT;

/* ─── Output: Region Entry ────────────────────────────────────────────── */
typedef struct _GGF_REGION {
    unsigned __int64 base;
    unsigned __int64 size;
} GGF_REGION, *PGGF_REGION;

/* ─── Output: Module Entry ────────────────────────────────────────────── */
typedef struct _GGF_MODULE {
    unsigned __int64 base;
    unsigned __int64 size;
    wchar_t          name[GGF_MODULE_NAME_LEN];
} GGF_MODULE, *PGGF_MODULE;

/* ─── Output Headers (variable-length arrays follow) ──────────────────── */
typedef struct _GGF_ENUM_REGIONS_OUT {
    unsigned long count;
    unsigned long _pad;
    GGF_REGION    regions[1];  /* [count] entries follow */
} GGF_ENUM_REGIONS_OUT, *PGGF_ENUM_REGIONS_OUT;

typedef struct _GGF_ENUM_MODULES_OUT {
    unsigned long count;
    unsigned long _pad;
    GGF_MODULE    modules[1];  /* [count] entries follow */
} GGF_ENUM_MODULES_OUT, *PGGF_ENUM_MODULES_OUT;

/* Buffer size calculations for user-mode allocation */
#define GGF_REGIONS_OUTBUF_SIZE  (sizeof(GGF_ENUM_REGIONS_OUT) + sizeof(GGF_REGION) * (GGF_MAX_REGIONS - 1))
#define GGF_MODULES_OUTBUF_SIZE  (sizeof(GGF_ENUM_MODULES_OUT) + sizeof(GGF_MODULE) * (GGF_MAX_MODULES - 1))
