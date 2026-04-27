/*
 * Freestanding C helpers for TEMPEST_PIC_SHELLCODE (no msvcrt / MSVCRT import).
 * Linked with -nostdlib; only symbols referenced from Stargate + glue resolve here.
 */
#include <stddef.h>

/* MinGW PE glue — referenced by CRT startup objects not linked with -nostdlib. */
void _pei386_runtime_relocator(void) {}

void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *a = (unsigned char *)d;
    const unsigned char *b = (const unsigned char *)s;
    while (n--) *a++ = *b++;
    return d;
}

void *memset(void *d, int c, size_t n)
{
    unsigned char *a = (unsigned char *)d;
    while (n--) *a++ = (unsigned char)c;
    return d;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++) {
        if (p[i] != q[i]) return p[i] - q[i];
    }
    return 0;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char *strncpy(char *d, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n && s[i]; i++) d[i] = s[i];
    for (; i < n; i++) d[i] = '\0';
    return d;
}

char *strrchr(const char *s, int c)
{
    char *last = (char *)0;
    for (; *s; s++) {
        if ((unsigned char)*s == (unsigned char)c) last = (char *)s;
    }
    if ((unsigned char)c == 0) return (char *)s;
    return last;
}
