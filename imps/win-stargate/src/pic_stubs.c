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

char *strcpy(char *d, const char *s)
{
    char *r = d;
    while ((*d++ = *s++)) {
    }
    return r;
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

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (; n && *a && *b; n--, a++, b--) {
        if ((unsigned char)*a != (unsigned char)*b)
            return (int)(unsigned char)*a - (int)(unsigned char)*b;
    }
    if (n == 0) return 0;
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char *strncat(char *d, const char *s, size_t n)
{
    char *p = d;
    while (*p) p++;
    while (n && *s) {
        *p++ = *s++;
        n--;
    }
    *p = 0;
    return d;
}

int atoi(const char *s)
{
    int v = 0, sign = 1;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') {
        sign = -1;
        s++;
    }
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    return sign * v;
}

int tempest_isspace(int c)
{
    unsigned char u = (unsigned char)c;
    return u == ' ' || u == '\t' || u == '\n' || u == '\r' || u == '\f' || u == '\v';
}

size_t wcslen(const wchar_t *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

wchar_t *wcscat(wchar_t *dest, const wchar_t *src)
{
    wchar_t *r = dest;
    while (*dest) dest++;
    while ((*dest++ = *src++)) {}
    return r;
}

wchar_t *wcsncat(wchar_t *dest, const wchar_t *src, size_t n)
{
    wchar_t *r = dest;
    while (*dest) dest++;
    while (n && *src) {
        *dest++ = *src++;
        n--;
    }
    *dest = 0;
    return r;
}

wchar_t *wcsstr(const wchar_t *haystack, const wchar_t *needle)
{
    if (!needle || !*needle) return (wchar_t *)haystack;
    for (; *haystack; haystack++) {
        const wchar_t *a = haystack;
        const wchar_t *b = needle;
        while (*a && *b && *a == *b) {
            a++;
            b++;
        }
        if (!*b) return (wchar_t *)haystack;
    }
    return (wchar_t *)0;
}
