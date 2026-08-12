/*
 * Declarations for TEMPEST_PIC_SHELLCODE builds (-nostdlib). Implemented in pic_stubs.c,
 * pic_snprintf.c, and heap helpers at end of tempest_c2.c.
 */
#ifndef PIC_FREESTANDING_H
#define PIC_FREESTANDING_H

#include <stddef.h>

void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
int strcmp(const char *a, const char *b);
char *strncpy(char *d, const char *s, size_t n);
char *strrchr(const char *s, int c);

size_t strlen(const char *s);
int strncmp(const char *a, const char *b, size_t n);
char *strncat(char *d, const char *s, size_t n);
int atoi(const char *s);
int isspace(int c);

void *malloc(size_t n);
void free(void *p);
void *realloc(void *p, size_t n);

int _snprintf(char *buf, size_t n, const char *fmt, ...);

#endif
