/*
 * PIC / flat shellcode build: no MSVCRT — declarations + snprintf shim for tempest_c2.c.
 * Heap: pic_heap.c (kernel32 Heap* via EAT). Strings/mem: pic_stubs.c.
 */
#ifndef TEMPEST_PIC_COMPAT_H
#define TEMPEST_PIC_COMPAT_H

#include <stddef.h>
#include <stdarg.h>

void *malloc(size_t n);
void free(void *p);
void *realloc(void *p, size_t n);

void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
size_t strlen(const char *s);
char *strcpy(char *d, const char *s);
char *strncpy(char *d, const char *s, size_t n);
int strncmp(const char *a, const char *b, size_t n);
char *strncat(char *d, const char *s, size_t n);
int atoi(const char *s);

#ifdef isspace
#undef isspace
#endif
/* Avoid mingw ctype dllimport vs our freestanding impl */
int tempest_isspace(int c);
#define isspace(X) tempest_isspace(X)

int pic_vsnprintf(char *buf, size_t sz, const char *fmt, va_list ap);
int pic_snprintf(char *buf, size_t sz, const char *fmt, ...);

#define _snprintf pic_snprintf
#define snprintf pic_snprintf

#endif
