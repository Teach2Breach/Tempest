/*
 * BM-T1002 Moonwalk - Signature Extraction Utility
 * 
 * Extracts clean function signatures from KnownDlls or System32 files.
 * This is the missing piece - how to get signatures at runtime!
 * 
 * Production-ready for F100 red teams.
 */

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "moonwalk.h"
#include "loader.h"

/* kernel32: resolve by FNV-1a (BM-T1001) — no static IAT for file mapping path */
#define H_NTCLOSE_              0xC6CF98E9u
#define H_K32_                  0xA25682A7u
#define H_GetSystemDirectoryW_  0xA1D8E3E2u
#define H_CreateFileW_          0x58025728u
#define H_CreateFileMappingW_   0x4DA76ACCu
#define H_MapViewOfFile_        0x4F6DC6DFu
#define H_UnmapViewOfFile_      0x8465D4BAu
#define H_CloseHandle_          0x7205C1B9u

typedef UINT (WINAPI *fn_GetSystemDirectoryW)(LPWSTR, UINT);
typedef HANDLE (WINAPI *fn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *fn_CreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI *fn_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI *fn_UnmapViewOfFile)(LPCVOID);
typedef BOOL (WINAPI *fn_CloseHandle)(HANDLE);

static int g_k32f_inited;
static int g_k32f_ok;
static fn_GetSystemDirectoryW s_GetSystemDirectoryW;
static fn_CreateFileW s_CreateFileW;
static fn_CreateFileMappingW s_CreateFileMappingW;
static fn_MapViewOfFile s_MapViewOfFile;
static fn_UnmapViewOfFile s_UnmapViewOfFile;
static fn_CloseHandle s_CloseHandle;

static int sig_k32_file_resolve(void)
{
    if (g_k32f_inited)
        return g_k32f_ok ? 0 : -1;
    g_k32f_inited = 1;
    HMODULE k = (HMODULE)locate_base(H_K32_);
    if (!k)
        return -1;
    s_GetSystemDirectoryW = (fn_GetSystemDirectoryW)(void *)resolve_addr(k, H_GetSystemDirectoryW_);
    s_CreateFileW = (fn_CreateFileW)(void *)resolve_addr(k, H_CreateFileW_);
    s_CreateFileMappingW = (fn_CreateFileMappingW)(void *)resolve_addr(k, H_CreateFileMappingW_);
    s_MapViewOfFile = (fn_MapViewOfFile)(void *)resolve_addr(k, H_MapViewOfFile_);
    s_UnmapViewOfFile = (fn_UnmapViewOfFile)(void *)resolve_addr(k, H_UnmapViewOfFile_);
    s_CloseHandle = (fn_CloseHandle)(void *)resolve_addr(k, H_CloseHandle_);
    if (!s_GetSystemDirectoryW || !s_CreateFileW || !s_CreateFileMappingW
        || !s_MapViewOfFile || !s_UnmapViewOfFile || !s_CloseHandle)
        return -1;
    g_k32f_ok = 1;
    return 0;
}

// NtOpenSection and NtMapViewOfSection declarations
typedef NTSTATUS (WINAPI *NtOpenSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (WINAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (WINAPI *NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef VOID (WINAPI *RtlInitUnicodeString_t)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

#define ViewShare 1
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

/*
 * extract_signature_from_knowndlls
 * 
 * Extracts a function signature from the clean \KnownDlls\ cached copy.
 * This is the PREFERRED method - no disk I/O, system-maintained clean copy.
 * 
 * Returns: 1 on success, 0 on failure
 */
int extract_signature_from_knowndlls(
    const wchar_t *dll_name,
    const char *func_name,
    unsigned char *sig_out,
    size_t sig_len,
    void **func_rva_out
) {
    if (!dll_name || !func_name || !sig_out || sig_len == 0) return 0;
    
    // Get ntdll functions dynamically
    HMODULE ntdll = find_module_base(L"ntdll.dll");
    if (!ntdll) return 0;
    
    NtOpenSection_t NtOpenSection = (NtOpenSection_t)resolve_export(ntdll, "NtOpenSection");
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)resolve_export(ntdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)resolve_export(ntdll, "NtUnmapViewOfSection");
    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)resolve_export(ntdll, "RtlInitUnicodeString");
    typedef NTSTATUS (NTAPI *fn_NtClose)(HANDLE);
    fn_NtClose pNtClose = (fn_NtClose)(void *)resolve_addr((HMODULE)ntdll, H_NTCLOSE_);
    
    if (!NtOpenSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !RtlInitUnicodeString || !pNtClose) return 0;
    
    // Build \KnownDlls\ntdll.dll path
    wchar_t known_dll_path[300] = L"\\KnownDlls\\";
    wcsncat(known_dll_path, dll_name, 250);
    
    // Ensure .dll extension
    if (!wcsstr(dll_name, L".dll")) {
        wcscat(known_dll_path, L".dll");
    }
    
    // Open KnownDlls section
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, known_dll_path);
    
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    HANDLE hSection = NULL;
    NTSTATUS st = NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (st != 0) return 0;
    
    // Map the clean DLL
    SIZE_T viewSize = 0;
    PVOID viewBase = NULL;
    st = NtMapViewOfSection(
        hSection,
        (HANDLE)-1,  // Current process
        &viewBase,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_READONLY
    );
    
    if (st != 0 || !viewBase) {
        pNtClose(hSection);
        return 0;
    }
    
    // Now we have a clean copy mapped - extract signature
    void *func_addr = resolve_export((HMODULE)viewBase, func_name);
    if (!func_addr) {
        NtUnmapViewOfSection((HANDLE)-1, viewBase);
        pNtClose(hSection);
        return 0;
    }
    
    // Extract signature bytes
    memcpy(sig_out, func_addr, sig_len);
    
    if (func_rva_out) {
        *func_rva_out = (void*)((unsigned char*)func_addr - (unsigned char*)viewBase);
    }
    
    // Cleanup
    NtUnmapViewOfSection((HANDLE)-1, viewBase);
    pNtClose(hSection);
    
    return 1;
}

/*
 * extract_signature_from_file
 * 
 * Fallback: Reads DLL from System32 directory on disk.
 * Less preferred than KnownDlls but still gets clean copy.
 * 
 * Returns: 1 on success, 0 on failure
 */
int extract_signature_from_file(
    const wchar_t *dll_name,
    const char *func_name,
    unsigned char *sig_out,
    size_t sig_len,
    void **func_rva_out
) {
    if (!dll_name || !func_name || !sig_out || sig_len == 0) return 0;
    if (sig_k32_file_resolve() != 0) return 0;
    
    // Build System32 path
    wchar_t sys_path[MAX_PATH];
    if (s_GetSystemDirectoryW(sys_path, MAX_PATH) == 0) return 0;
    
    wcscat(sys_path, L"\\");
    wcsncat(sys_path, dll_name, MAX_PATH - wcslen(sys_path) - 1);
    
    // Ensure .dll extension
    if (!wcsstr(dll_name, L".dll")) {
        wcscat(sys_path, L".dll");
    }
    
    // Open file
    HANDLE hFile = s_CreateFileW(
        sys_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    // Create file mapping
    HANDLE hMap = s_CreateFileMappingW(
        hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );
    
    if (!hMap) {
        s_CloseHandle(hFile);
        return 0;
    }
    
    // Map view
    PVOID viewBase = s_MapViewOfFile(
        hMap,
        FILE_MAP_READ,
        0,
        0,
        0
    );
    
    if (!viewBase) {
        s_CloseHandle(hMap);
        s_CloseHandle(hFile);
        return 0;
    }
    
    // Extract signature from mapped file
    void *func_addr = resolve_export((HMODULE)viewBase, func_name);
    if (!func_addr) {
        s_UnmapViewOfFile(viewBase);
        s_CloseHandle(hMap);
        s_CloseHandle(hFile);
        return 0;
    }
    
    // Extract bytes
    memcpy(sig_out, func_addr, sig_len);
    
    if (func_rva_out) {
        *func_rva_out = (void*)((unsigned char*)func_addr - (unsigned char*)viewBase);
    }
    
    // Cleanup
    s_UnmapViewOfFile(viewBase);
    s_CloseHandle(hMap);
    s_CloseHandle(hFile);
    
    return 1;
}

/*
 * extract_clean_signature
 * 
 * Main entry point - tries KnownDlls first, falls back to file.
 * This is production-ready signature extraction.
 * 
 * Returns: 1 on success, 0 on failure
 */
int extract_clean_signature(
    const wchar_t *dll_name,
    const char *func_name,
    unsigned char *sig_out,
    size_t sig_len
) {
    // Try KnownDlls first (preferred - no disk I/O, always clean)
    if (extract_signature_from_knowndlls(dll_name, func_name, sig_out, sig_len, NULL)) {
        return 1;
    }
    
    // Fallback to file mapping
    return extract_signature_from_file(dll_name, func_name, sig_out, sig_len, NULL);
}

/*
 * extract_clean_signature_at_offset
 * 
 * Extracts signature from middle of function (bypasses prologue hooks).
 * Hooks typically modify first 5-15 bytes, so offset 24+ is usually clean.
 * 
 * Returns: 1 on success, 0 on failure
 */
int extract_clean_signature_at_offset(
    const wchar_t *dll_name,
    const char *func_name,
    size_t offset,
    unsigned char *sig_out,
    size_t sig_len
) {
    if (!dll_name || !func_name || !sig_out || sig_len == 0) return 0;
    
    // First extract full signature
    unsigned char full_sig[256];
    if (offset + sig_len > sizeof(full_sig)) return 0;
    
    if (!extract_clean_signature(dll_name, func_name, full_sig, offset + sig_len)) {
        return 0;
    }
    
    // Copy from offset
    memcpy(sig_out, full_sig + offset, sig_len);
    return 1;
}

