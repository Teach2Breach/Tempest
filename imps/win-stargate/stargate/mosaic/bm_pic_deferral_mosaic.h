/*
 * Vendored for Tempest (imps/win-stargate). Do not #include from ../../techniques/ —
 * builds must not depend on the techniques/ tree. Upstream: techniques/BM-T6003.
 *
 * BM-T6003 Deferral Mosaic — PIC-first multi-lane sleep (strict round-robin).
 * PE beacons keep Morpheus (stargate/morpheus); raw beacon.bin uses this only.
 */

#ifndef BM_PIC_DEFERRAL_MOSAIC_H
#define BM_PIC_DEFERRAL_MOSAIC_H

typedef struct deferral_mosaic_ctx deferral_mosaic_ctx;

#define MOSAIC_OK           0
#define MOSAIC_ERR_RESOLVE  1

/*
 * Bootstrap: RtlHeap alloc + hashed EAT resolves (timer queue, events, keyed NT).
 * Module bases come from PIC PEB walk (bm_pic_entry mod_h pattern).
 */
int deferral_mosaic_init(void *ntdll_base, void *kernel32_base,
                         deferral_mosaic_ctx **out_ctx);

void deferral_mosaic_sleep(deferral_mosaic_ctx *ctx, unsigned int ms_dw);

void deferral_mosaic_free(deferral_mosaic_ctx *ctx);

/* Diagnostics: lane index last used by deferral_mosaic_sleep (0..2), or ~0 before first sleep */
unsigned deferral_mosaic_last_lane(const deferral_mosaic_ctx *ctx);

#endif /* BM_PIC_DEFERRAL_MOSAIC_H */
