#ifndef SYSCALLS_H
#define SYSCALLS_H

/*
 * BM-T1003/T1005: Direct Syscall Invocation — Header
 *
 * SSN extraction + generic direct syscall stubs for Windows x64.
 *
 * invoke_syscall_N(DWORD ssn, arg1, arg2, ..., argN)
 *
 * The SSN is passed as the first C argument; all NT args shift right.
 * Supports 0-11 arguments (covers all known NT syscalls).
 *
 * Platform: Windows x64 only
 */

#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * SSN Extraction
 * ======================================================================== */

/*
 * extract_ssn — Extract the System Service Number from an NT function stub.
 *
 * Scans the first bytes of the function for the pattern:
 *   4C 8B D1    mov r10, rcx
 *   B8 XX XX 00 00   mov eax, <SSN>
 *
 * @param func_addr: Address of the NT function (from EAT resolution)
 * @return: SSN value (>0), or 0 on failure (pattern not found / hooked).
 */
DWORD extract_ssn(void *func_addr);

/*
 * extract_ssn_with_fallback — SSN extraction with Tartarus' Gate fallback.
 *
 * First tries standard extraction (extract_ssn). If the stub is hooked and
 * the pattern is destroyed, activates Tartarus' Gate: scans neighboring
 * stubs (spaced 0x20 bytes apart) in both directions for clean stubs and
 * infers the target SSN by offset.
 *
 * @param func_addr:  Address of the NT function
 * @param ntdll_base: Base address of ntdll (for .text section bounds)
 * @return: SSN value (>0), or 0 on failure.
 */
DWORD extract_ssn_with_fallback(void *func_addr, void *ntdll_base);

/* ========================================================================
 * Generic Direct Syscall Stubs (SSN as first parameter)
 *
 * invoke_syscall_N(DWORD ssn, arg1, arg2, ..., argN)
 *
 * The SSN is passed in ECX (first C arg). The stub moves it to EAX,
 * shifts the remaining args into the NT calling convention positions,
 * and executes `syscall; ret` from implant memory.
 *
 * Cast all pointer/integer args to (void *) when calling.
 * ======================================================================== */

NTSTATUS invoke_syscall_0(DWORD ssn);
NTSTATUS invoke_syscall_1(DWORD ssn, void *a1);
NTSTATUS invoke_syscall_2(DWORD ssn, void *a1, void *a2);
NTSTATUS invoke_syscall_3(DWORD ssn, void *a1, void *a2, void *a3);
NTSTATUS invoke_syscall_4(DWORD ssn, void *a1, void *a2, void *a3, void *a4);
NTSTATUS invoke_syscall_5(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5);
NTSTATUS invoke_syscall_6(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6);
NTSTATUS invoke_syscall_7(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7);
NTSTATUS invoke_syscall_8(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8);
NTSTATUS invoke_syscall_9(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9);
NTSTATUS invoke_syscall_10(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10);
NTSTATUS invoke_syscall_11(DWORD ssn, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10, void *a11);

#ifdef __cplusplus
}
#endif

#endif /* SYSCALLS_H */
