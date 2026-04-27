/* Anvil C2 (HTTPS /js, /index, /return_out) using WinHTTP + Windows CNG (BCrypt). */
#ifndef TEMPEST_C2_H
#define TEMPEST_C2_H

struct morpheus_ctx;

/* morph: BM-T6001 Morpheus context (required for production C2; interval sleep). */
void tempest_c2_run(struct morpheus_ctx *morph);

#endif
