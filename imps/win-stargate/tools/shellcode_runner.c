/*
 * Lab harness: map a raw shellcode .bin, jump to shellcode_entry (x64, Windows).
 * Build (cross, from imps/win-stargate):  make runner
 *
 * Usage:
 *   tools\shellcode_runner.exe [path\to\beacon.bin] [entry_offset_hex] [alloc_base_hex]
 *
 * - The flat .bin from "make raw" is .rdata + .text + .data concatenated. The first byte
 *   is NOT the entry — code starts after the .rdata prefix. "make raw" also writes
 *   path.entry_offset (same name as the .bin plus ".entry_offset") with one hex line.
 *   If you omit entry_offset_hex, the runner reads that sidecar next to the binary.
 * - alloc_base_hex: optional VirtualAlloc hint (e.g. 0x0000014000000000). Often NULL is fine
 *   if the shellcode is position-independent.
 * - If the shellcode returns, you will see "returned" on the console.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

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

/* path + ".entry_offset" e.g. beacon.bin -> beacon.bin.entry_offset */
static int read_sidecar_offset(const char *path, unsigned long long *out)
{
    static const char suf[] = ".entry_offset";
    size_t plen = strlen(path);
    char *side = (char *)malloc(plen + sizeof suf);
    if (!side) return 0;
    memcpy(side, path, plen);
    memcpy(side + plen, suf, sizeof suf);

    FILE *f = fopen(side, "r");
    free(side);
    if (!f) return 0;
    char buf[128];
    if (!fgets(buf, sizeof buf, f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    int ok = 0;
    *out = parse_hex(buf, &ok);
    return ok;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "beacon.bin";
    unsigned long long entry_off = 0;
    int have_entry = 0;

    if (argc > 2) {
        int ok = 0;
        entry_off = parse_hex(argv[2], &ok);
        if (ok) have_entry = 1;
    }
    if (!have_entry) {
        unsigned long long sc = 0;
        if (read_sidecar_offset(path, &sc)) {
            entry_off = sc;
            have_entry = 1;
        }
    }
    if (!have_entry) {
        fprintf(stderr,
                "shellcode_runner: missing entry offset. Build with \"make raw\" and copy "
                "%s.entry_offset next to the binary, or pass offset in hex as argv[2] "
                "(see imps/win-stargate/README.md).\n",
                path);
        return 1;
    }

    void *fixed = NULL;
    if (argc > 3) {
        int ok = 0;
        unsigned long long u = parse_hex(argv[3], &ok);
        if (ok && u != 0) fixed = (void *)(uintptr_t)u;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "shellcode_runner: cannot open %s\n", path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 1) {
        fprintf(stderr, "shellcode_runner: file empty or size error: %s\n", path);
        fclose(f);
        return 1;
    }

    if ((unsigned long long)n < entry_off) {
        fprintf(stderr, "shellcode_runner: entry offset 0x%llx past end of file (%ld)\n",
                (unsigned long long)entry_off, n);
        fclose(f);
        return 1;
    }

    void *map = NULL;
    if (fixed) {
        map = VirtualAlloc(fixed, (SIZE_T)n, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!map) {
            fprintf(stderr,
                    "shellcode_runner: VirtualAlloc at %p failed (err %lu) — try without base.\n",
                    fixed, (unsigned long)GetLastError());
            return 1;
        }
    } else {
        map = VirtualAlloc(NULL, (SIZE_T)n, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!map) {
        fprintf(stderr, "shellcode_runner: VirtualAlloc failed: %lu\n", (unsigned long)GetLastError());
        fclose(f);
        return 1;
    }

    if (fread(map, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "shellcode_runner: short read from %s\n", path);
        VirtualFree(map, 0, MEM_RELEASE);
        fclose(f);
        return 1;
    }
    fclose(f);

    unsigned char *entry = (unsigned char *)map + entry_off;
    FlushInstructionCache(GetCurrentProcess(), entry, (SIZE_T)(n - (long)entry_off));

    printf("shellcode_runner: %ld bytes at %p, entry at +0x%llx (%p)", n, map,
           (unsigned long long)entry_off, (void *)entry);
    if (fixed) printf(", alloc hint %p", fixed);
    printf(" — calling...\n");
    fflush(stdout);

    void (*sc)(void) = (void (*)(void))entry;
    sc();

    printf("shellcode_runner: returned from shellcode.\n");
    VirtualFree(map, 0, MEM_RELEASE);
    return 0;
}
