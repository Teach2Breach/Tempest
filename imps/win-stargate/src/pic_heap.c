/*
 * PIC heap: kernel32 HeapAlloc/HeapFree/HeapReAlloc via EAT (no .idata — compatible with shellcode.ld).
 */
#include <stddef.h>
#include <windows.h>
#include "loader.h"

#define H_K32_HEAP 0xa25682a7u

typedef HANDLE(WINAPI *pGetProcessHeap_t)(void);
typedef LPVOID(WINAPI *pHeapAlloc_t)(HANDLE, DWORD, SIZE_T);
typedef BOOL(WINAPI *pHeapFree_t)(HANDLE, DWORD, LPVOID);
typedef LPVOID(WINAPI *pHeapReAlloc_t)(HANDLE, DWORD, LPVOID, SIZE_T);

static pGetProcessHeap_t fn_GetProcessHeap;
static pHeapAlloc_t fn_HeapAlloc;
static pHeapFree_t fn_HeapFree;
static pHeapReAlloc_t fn_HeapReAlloc;

static int pic_heap_resolve(void)
{
    HMODULE k32 = (HMODULE)locate_base(H_K32_HEAP);
    if (!k32) return -1;
    fn_GetProcessHeap = (pGetProcessHeap_t)(void *)resolve_addr(k32, hash_name("GetProcessHeap"));
    fn_HeapAlloc = (pHeapAlloc_t)(void *)resolve_addr(k32, hash_name("HeapAlloc"));
    fn_HeapFree = (pHeapFree_t)(void *)resolve_addr(k32, hash_name("HeapFree"));
    fn_HeapReAlloc = (pHeapReAlloc_t)(void *)resolve_addr(k32, hash_name("HeapReAlloc"));
    if (!fn_GetProcessHeap || !fn_HeapAlloc || !fn_HeapFree || !fn_HeapReAlloc) return -1;
    return 0;
}

void *malloc(size_t n)
{
    if (!fn_HeapAlloc && pic_heap_resolve()) return NULL;
    SIZE_T req = n ? n : 1;
    return fn_HeapAlloc(fn_GetProcessHeap(), 0, req);
}

void free(void *p)
{
    if (!p || !fn_HeapFree) return;
    fn_HeapFree(fn_GetProcessHeap(), 0, p);
}

void *realloc(void *p, size_t n)
{
    if (!fn_HeapReAlloc && pic_heap_resolve()) return NULL;
    HANDLE h = fn_GetProcessHeap();
    if (!p) return fn_HeapAlloc(h, 0, n ? n : 1);
    if (!n) {
        fn_HeapFree(h, 0, p);
        return NULL;
    }
    return fn_HeapReAlloc(h, 0, p, n);
}
