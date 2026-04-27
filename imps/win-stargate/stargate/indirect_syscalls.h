/*
 * BM-T1004/T1005: Indirect Syscalls — Header
 *
 * Extends BM-T1003 (Direct Syscalls) by executing the `syscall` instruction
 * from within ntdll.dll's own memory via a cached gadget trampoline.
 * Defeats EDR return-address validation.
 *
 * indirect_syscall_N(DWORD ssn, arg1, arg2, ..., argN)
 *
 * Same shift logic as the direct generic stubs, but tail is:
 *   jmp [g_syscall_gadget]   instead of   syscall; ret
 *
 * Supports 0-11 arguments (covers all known NT syscalls).
 *
 * Dependencies:
 *   - BM-T1002 (moonwalk.h/c): Stack-based ntdll discovery (PREFERRED)
 *   - BM-T1001 (loader.h/c): Hash-based EAT resolution
 *   - BM-T1003 (syscalls.h/c): SSN extraction (extract_ssn)
 *
 * Platform: Windows x64 only
 */

#ifndef INDIRECT_SYSCALLS_H
#define INDIRECT_SYSCALLS_H

#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Gadget Discovery
 * ======================================================================== */

/*
 * find_syscall_gadget — Scan a module's .text section for a syscall;ret gadget.
 *
 * Searches for the byte sequence 0F 05 C3 (syscall; ret).
 *
 * @param module_base: Base address of the PE module (e.g. ntdll)
 * @return: Address of the syscall instruction, or NULL.
 */
void *find_syscall_gadget(void *module_base);

/*
 * find_syscall_gadget_near — Find gadget within +range_bytes of a function.
 *
 * Some EDRs validate proximity of the gadget to the expected NT stub.
 *
 * @param func_addr: Address of the NT function
 * @param range_bytes: Search range (typically 32-512 bytes)
 * @return: Address of a nearby syscall instruction, or NULL.
 */
void *find_syscall_gadget_near(void *func_addr, size_t range_bytes);

/* ========================================================================
 * Global State
 * ======================================================================== */

/* Cached gadget address — points to `syscall; ret` inside ntdll.
 * Set by sg_init() (shared gadget) or sg_call_N() (per-function gadget). */
extern void *g_syscall_gadget;

/* ========================================================================
 * Generic Indirect Syscall Stubs (SSN as first parameter)
 *
 * indirect_syscall_N(DWORD ssn, arg1, arg2, ..., argN)
 *
 * Same calling convention as invoke_syscall_N, but the tail instruction
 * jumps to the gadget in ntdll instead of executing syscall directly.
 *
 * Cast all pointer/integer args to (void *) when calling.
 * ======================================================================== */

NTSTATUS indirect_syscall_0(DWORD ssn);
NTSTATUS indirect_syscall_1(DWORD ssn, void *a1);
NTSTATUS indirect_syscall_2(DWORD ssn, void *a1, void *a2);
NTSTATUS indirect_syscall_3(DWORD ssn, void *a1, void *a2, void *a3);
NTSTATUS indirect_syscall_4(DWORD ssn, void *a1, void *a2, void *a3, void *a4);
NTSTATUS indirect_syscall_5(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5);
NTSTATUS indirect_syscall_6(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6);
NTSTATUS indirect_syscall_7(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7);
NTSTATUS indirect_syscall_8(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8);
NTSTATUS indirect_syscall_9(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9);
NTSTATUS indirect_syscall_10(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10);
NTSTATUS indirect_syscall_11(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10, void *a11);

/* ========================================================================
 * Initialization Helper (standalone BM-T1004 use only)
 *
 * Note: When using through Stargate (BM-T1005), initialization is handled
 * by sg_init() which uses a more resilient string-based approach.
 * ======================================================================== */

int init_indirect_syscalls(void *ntdll_base);

#ifdef __cplusplus
}
#endif

#endif /* INDIRECT_SYSCALLS_H */
