/*
 * BM-T1002 Moonwalk - OPSEC-Clean Library Header
 * 
 * Stack-based module discovery without PEB walk or EAT enumeration.
 * Based on Teach2Breach's Moonwalk technique from Stargate.
 * 
 * Production-ready: No revealing strings in compiled library.
 * Combine with BM-T1001 for hash-based lookups or use wide strings directly.
 */

#ifndef MOONWALK_H
#define MOONWALK_H

#include <windows.h>

/*
 * find_module_base
 * 
 * Discovers a loaded DLL's base address by walking the current thread's stack,
 * harvesting return addresses, and scanning backwards for PE headers.
 * 
 * This avoids:
 * - PEB walking (InLoadOrderModuleList)
 * - Calling GetModuleHandle/LoadLibrary
 * - Any documented Windows API for module enumeration
 * 
 * Parameters:
 *   dll_name: Wide-character DLL name (case-insensitive, .dll extension optional)
 *             Example: L"ntdll", L"ntdll.dll", L"KERNEL32"
 * 
 * Returns:
 *   Module base address (HMODULE) if found
 *   NULL if not found or not in call stack
 * 
 * OPSEC Notes:
 *   - Only finds modules that are in the current call stack
 *   - Requires at least one return address into target DLL
 *   - Uses structured exception handling for safe memory access
 *   - No suspicious API calls (only intrinsics and direct memory reads)
 */
HMODULE find_module_base(const wchar_t *dll_name);

/*
 * resolve_export
 * 
 * Locates a function address by parsing the Export Address Table of a module
 * discovered via stack walking. Use find_module_base() first to get the base.
 * 
 * Parameters:
 *   module_base: Base address from find_module_base()
 *   func_name:   ANSI function name (case-sensitive)
 * 
 * Returns:
 *   Function address if found
 *   NULL if not found or export table invalid
 * 
 * OPSEC Notes:
 *   - Parses EAT directly from memory (no WinAPI)
 *   - Case-sensitive comparison (Windows standard)
 *   - Handles forwarded exports (returns forwarder RVA, caller must resolve)
 */
void* resolve_export(HMODULE module_base, const char *func_name);

/*
 * Hook detection structures
 */
typedef enum {
    HOOK_NONE = 0,
    HOOK_JMP_REL32,      // E9 xx xx xx xx (5 bytes)
    HOOK_JMP_REL8,       // EB xx (2 bytes)
    HOOK_CALL_REL32,     // E8 xx xx xx xx (5 bytes)
    HOOK_PUSH_RET,       // 68 xx xx xx xx C3 (6 bytes)
    HOOK_MOV_JMP,        // 48 B8 ... FF E0 (12 bytes)
    HOOK_INLINE,         // Modified bytes in middle of function
    HOOK_UNKNOWN
} HOOK_TYPE;

typedef struct {
    int is_hooked;                    // 1 if hook detected, 0 otherwise
    HOOK_TYPE hook_type;              // Type of hook found
    size_t hook_offset;               // Offset from function start
    void *jump_target;                // Where hook redirects (if applicable)
    unsigned char original_bytes[24]; // Clean bytes from signature
    unsigned char hooked_bytes[24];   // Actual bytes in memory
    size_t bytes_len;                 // Number of bytes compared
    float match_ratio;                // Percentage of bytes matching (0.0-1.0)
} HOOK_INFO;

/*
 * scan_for_pattern
 * 
 * Scans module memory for a byte pattern, completely avoiding EAT enumeration.
 * This is the full Moonwalk/Stargate approach - find functions by signature.
 * 
 * Parameters:
 *   module_base: Base address from find_module_base()
 *   pattern:     Byte sequence to search for (function prologue/body)
 *   pattern_len: Length of pattern in bytes
 *   scan_size:   How many bytes to scan (e.g., 0x200000 for 2MB)
 * 
 * Returns:
 *   Address of first match, or NULL if not found
 * 
 * OPSEC Notes:
 *   - Does NOT access export table at all
 *   - More stealthy than EAT parsing (no name table access)
 *   - Requires known function signatures (prepare offline)
 *   - Can skip hooked prologues and find real function body
 *   - Used by Stargate for complete stealth
 */
void* scan_for_pattern(HMODULE module_base, const unsigned char *pattern, size_t pattern_len, size_t scan_size);

/*
 * scan_with_hook_detection
 * 
 * Advanced scanning with hook detection and partial matching.
 * Tries multiple strategies to find function even when hooked.
 * 
 * Parameters:
 *   module_base:  Base address from find_module_base()
 *   clean_sig:    Clean signature from extract_clean_signature()
 *   sig_len:      Signature length
 *   scan_size:    How many bytes to scan
 *   hook_info:    Output - hook detection results (can be NULL)
 * 
 * Returns:
 *   Function address if found, NULL otherwise
 * 
 * Strategies:
 *   1. Exact match (no hook)
 *   2. Partial match (hook at start, body intact)
 *   3. Body signature match (scan deeper into function)
 *   4. Hook detection and classification
 * 
 * OPSEC Notes:
 *   - Does NOT unhook or modify memory
 *   - Only detects and works around hooks
 *   - Combine with BM-TXXXX (Unhooking) if you need restoration
 */
void* scan_with_hook_detection(
    HMODULE module_base,
    const unsigned char *clean_sig,
    size_t sig_len,
    size_t scan_size,
    HOOK_INFO *hook_info
);

/*
 * extract_clean_signature
 * 
 * Extracts function signature from a clean DLL copy (KnownDlls or System32 disk file).
 * This is the Stargate approach - get signatures from unhooked sources at runtime.
 * 
 * Parameters:
 *   dll_name:  DLL name (e.g., L"ntdll", L"kernel32.dll")
 *   func_name: Function name (e.g., "NtAllocateVirtualMemory")
 *   sig_out:   Buffer to receive signature bytes
 *   sig_len:   Number of bytes to extract
 * 
 * Returns:
 *   1 on success, 0 on failure
 * 
 * Implementation:
 *   1. Tries \KnownDlls\<dll> first (preferred - cached clean copy)
 *   2. Falls back to C:\Windows\System32\<dll> file mapping
 *   3. Parses clean PE, finds function in EAT
 *   4. Extracts first sig_len bytes
 * 
 * OPSEC Notes:
 *   - Reads from CLEAN sources (unhooked)
 *   - Can be done at runtime (no prep phase needed)
 *   - KnownDlls has no disk I/O
 *   - Signatures can be cached/embedded after first extraction
 */
int extract_clean_signature(const wchar_t *dll_name, const char *func_name, unsigned char *sig_out, size_t sig_len);

/*
 * extract_clean_signature_at_offset
 * 
 * Extracts signature from middle of function body (bypasses prologue hooks).
 * Useful when function prologue is hooked but body is intact.
 * 
 * Parameters:
 *   dll_name:  DLL name
 *   func_name: Function name
 *   offset:    Byte offset from function start (e.g., 24 to skip prologue)
 *   sig_out:   Buffer to receive signature bytes
 *   sig_len:   Number of bytes to extract
 * 
 * Returns:
 *   1 on success, 0 on failure
 * 
 * OPSEC Notes:
 *   - Hooks typically modify first 5-15 bytes
 *   - Function body after offset 24 is usually clean
 *   - Use this for resilience against prologue hooks
 */
int extract_clean_signature_at_offset(
    const wchar_t *dll_name,
    const char *func_name,
    size_t offset,
    unsigned char *sig_out,
    size_t sig_len
);

#endif // MOONWALK_H

