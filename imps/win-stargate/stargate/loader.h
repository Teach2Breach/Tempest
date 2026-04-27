/*
 * Runtime Loader - Header
 * 
 * OPSEC-CLEAN LIBRARY - NO STRINGS, NO DEBUG OUTPUT
 * 
 * Generic runtime function resolution without debug output
 * or hardcoded identifiers.
 * 
 * Platform: Windows x64
 * License: MIT (see LICENSE-SNIPPETS)
 */

#ifndef LOADER_H
#define LOADER_H

#include <windows.h>
#include <winternl.h>

// ============================================================================
// Structure Definitions (Undocumented Windows Internals)
// ============================================================================

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
} LDR_DATA_TABLE_ENTRY_CUSTOM, *PLDR_DATA_TABLE_ENTRY_CUSTOM;

// ============================================================================
// Core API Resolution Functions
// ============================================================================

/*
 * hash_name - Hash an ASCII string (FNV-1a 32-bit)
 * 
 * @param str: Null-terminated ASCII string to hash
 * @return: 32-bit hash value (case-insensitive)
 * 
 * Note: Used for function names (EAT exports)
 */
DWORD hash_name(const char *str);

/*
 * hash_name_wide - Hash a wide string (FNV-1a 32-bit)
 * 
 * @param str: Null-terminated wide string to hash
 * @return: 32-bit hash value (case-insensitive)
 * 
 * Note: Used for module names (PEB entries)
 */
DWORD hash_name_wide(const wchar_t *str);

/*
 * locate_base - Locate loaded component by identifier
 * 
 * @param id: Pre-computed identifier
 * @return: Base address, or NULL if not found
 */
HMODULE locate_base(DWORD id);

/*
 * resolve_addr - Resolve address by identifier
 * 
 * @param base: Base address (from locate_base)
 * @param id: Pre-computed identifier
 * @return: Address, or NULL if not found
 */
FARPROC resolve_addr(HMODULE base, DWORD id);

#endif // LOADER_H

