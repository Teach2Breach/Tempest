/*
 * Runtime Loader - Implementation
 * 
 * OPSEC-CLEAN LIBRARY - NO STRINGS, NO DEBUG OUTPUT
 * 
 * Production-ready implementation with zero OPSEC violations:
 * - No printf/debug output
 * - No hardcoded identifiers
 * - No revealing comments in binary
 * 
 * Platform: Windows x64
 * License: MIT (see LICENSE-SNIPPETS)
 */

#include "loader.h"

// ============================================================================
// Hash Function: FNV-1a 32-bit (ASCII) — custom offset 0x9E3779B9 (BlackMagick)
// ============================================================================

DWORD hash_name(const char *str) {
    DWORD h = 0x9E3779B9u;
    for (; *str; str++) {
        unsigned char c = (unsigned char)*str;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

// ============================================================================
// Hash Function: FNV-1a 32-bit (Wide/Unicode)
// ============================================================================

DWORD hash_name_wide(const wchar_t *str) {
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

// ============================================================================
// Component Location
// ============================================================================

HMODULE locate_base(DWORD target_hash) {
    /* TEB via GS:[0x30] (self-ptr, commonly accessed); PEB at TEB+0x60 */
    BYTE *teb = (BYTE *)__readgsqword(0x30);
    PEB *peb = teb ? (PEB *)*(void **)(teb + 0x60) : NULL;
    
    if (!peb) {
        return NULL;
    }
    
    PEB_LDR_DATA *ldr = peb->Ldr;
    
    if (!ldr) {
        return NULL;
    }
    
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *current = head->Flink;
    
    while (current != head) {
        LDR_DATA_TABLE_ENTRY_CUSTOM *entry = CONTAINING_RECORD(
            current, 
            LDR_DATA_TABLE_ENTRY_CUSTOM, 
            InMemoryOrderLinks
        );
        
        if (entry->BaseDllName.Buffer) {
            DWORD module_hash = hash_name_wide(entry->BaseDllName.Buffer);
            
            if (module_hash == target_hash) {
                return (HMODULE)entry->DllBase;
            }
        }
        
        current = current->Flink;
    }
    
    return NULL;
}

// ============================================================================
// Address Resolution
// ============================================================================

FARPROC resolve_addr(HMODULE module, DWORD target_hash) {
    if (!module) {
        return NULL;
    }
    
    BYTE *base = (BYTE *)module;
    
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)base;
    
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)(base + dos_header->e_lfanew);
    
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    IMAGE_DATA_DIRECTORY *export_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    if (export_dir->VirtualAddress == 0) {
        return NULL;
    }
    
    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + export_dir->VirtualAddress);
    
    DWORD *name_rvas = (DWORD *)(base + exports->AddressOfNames);
    WORD *ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);
    DWORD *func_rvas = (DWORD *)(base + exports->AddressOfFunctions);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char *func_name = (char *)(base + name_rvas[i]);
        
        DWORD func_hash = hash_name(func_name);
        
        if (func_hash == target_hash) {
            WORD ordinal = ordinals[i];
            DWORD func_rva = func_rvas[ordinal];
            
            /* Check for forwarded export (RVA points inside export directory) */
            if (func_rva >= export_dir->VirtualAddress && 
                func_rva < export_dir->VirtualAddress + export_dir->Size) {
                /*
                 * Forwarded export — string like "sspicli.LsaOpenPolicy"
                 *
                 * Modern Windows forwards many advapi32 exports to sspicli,
                 * sechost, etc.  We parse the forward string, find the target
                 * DLL in the PEB, and recursively resolve.
                 */
                char *fwd = (char *)(base + func_rva);
                char dll_buf[128];
                int k = 0;

                /* Copy DLL name portion (before the dot) */
                while (fwd[k] && fwd[k] != '.' && k < 120) {
                    dll_buf[k] = fwd[k];
                    k++;
                }
                if (fwd[k] != '.')
                    return NULL;

                /* Append ".dll" */
                dll_buf[k]     = '.';
                dll_buf[k + 1] = 'd';
                dll_buf[k + 2] = 'l';
                dll_buf[k + 3] = 'l';
                dll_buf[k + 4] = '\0';

                /* ASCII FNV-1a hash matches wide hash for ASCII-range chars */
                DWORD fwd_dll_hash = hash_name(dll_buf);
                HMODULE fwd_mod = locate_base(fwd_dll_hash);
                if (!fwd_mod)
                    return NULL;

                /* Hash the function name part (after the dot) */
                char *fwd_func = fwd + k + 1;
                DWORD fwd_func_hash = hash_name(fwd_func);

                return resolve_addr(fwd_mod, fwd_func_hash);
            }
            
            return (FARPROC)(base + func_rva);
        }
    }
    
    return NULL;
}
