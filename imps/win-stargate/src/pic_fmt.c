/*
 * Minimal snprintf for PIC build (tempest_c2 trace: %s %d %u %lu %zu %lx %p, plus %.N ignores precision).
 */
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include "tempest_pic_compat.h"

static void pic_putc(char **out, size_t *cap, size_t *total, char c)
{
    (*total)++;
    if (*cap > 1) {
        **out = c;
        (*out)++;
        (*cap)--;
    }
}

static void pic_puts(char **out, size_t *cap, size_t *total, const char *s)
{
    if (!s) s = "(null)";
    while (*s) pic_putc(out, cap, total, *s++);
}

static void pic_put_ulong(char **out, size_t *cap, size_t *total, unsigned long v)
{
    char tmp[22];
    int i = 0;
    if (v == 0) {
        pic_putc(out, cap, total, '0');
        return;
    }
    while (v) {
        tmp[i++] = (char)('0' + (v % 10ul));
        v /= 10ul;
    }
    while (i--) pic_putc(out, cap, total, tmp[i]);
}

static void pic_put_int(char **out, size_t *cap, size_t *total, int v)
{
    if (v < 0) {
        pic_putc(out, cap, total, '-');
        pic_put_ulong(out, cap, total, (unsigned long)(unsigned int)(-(unsigned int)v));
    } else {
        pic_put_ulong(out, cap, total, (unsigned long)(unsigned int)v);
    }
}

static void pic_put_hex_ul(char **out, size_t *cap, size_t *total, unsigned long v)
{
    static const char xd[] = "0123456789abcdef";
    char tmp[sizeof(unsigned long) * 2];
    int i = 0;
    if (v == 0) {
        pic_putc(out, cap, total, '0');
        return;
    }
    while (v) {
        tmp[i++] = xd[v & 0xFUL];
        v >>= 4;
    }
    while (i--) pic_putc(out, cap, total, tmp[i]);
}

int pic_vsnprintf(char *buf, size_t sz, const char *fmt, va_list ap)
{
    char *out = buf;
    size_t cap = sz;
    size_t total = 0;

    if (sz > 0 && buf) buf[0] = '\0';

    while (*fmt) {
        if (*fmt != '%') {
            pic_putc(&out, &cap, &total, *fmt++);
            continue;
        }
        fmt++;
        if (*fmt == '%') {
            pic_putc(&out, &cap, &total, '%');
            fmt++;
            continue;
        }
        while (*fmt == '0' || *fmt == '-' || *fmt == ' ' || *fmt == '+' || *fmt == '#') fmt++;
        while (*fmt >= '0' && *fmt <= '9') fmt++;
        if (*fmt == '.') {
            fmt++;
            while (*fmt >= '0' && *fmt <= '9') fmt++;
        }
        if (*fmt == 'l' && fmt[1] == 'u') {
            fmt += 2;
            pic_put_ulong(&out, &cap, &total, va_arg(ap, unsigned long));
            continue;
        }
        if (*fmt == 'l' && fmt[1] == 'x') {
            fmt += 2;
            pic_put_hex_ul(&out, &cap, &total, va_arg(ap, unsigned long));
            continue;
        }
        if (*fmt == 'z' && fmt[1] == 'u') {
            fmt += 2;
            pic_put_ulong(&out, &cap, &total, (unsigned long)va_arg(ap, size_t));
            continue;
        }
        if (*fmt == 'd') {
            fmt++;
            pic_put_int(&out, &cap, &total, va_arg(ap, int));
            continue;
        }
        if (*fmt == 'p') {
            fmt++;
            pic_put_hex_ul(&out, &cap, &total,
                           (unsigned long)(uintptr_t)va_arg(ap, void *));
            continue;
        }
        if (*fmt == 's') {
            fmt++;
            pic_puts(&out, &cap, &total, va_arg(ap, const char *));
            continue;
        }
        if (*fmt) fmt++;
    }

    if (sz > 0 && buf && cap >= 1) *out = '\0';

    return (int)(total > (size_t)INT_MAX ? INT_MAX : total);
}

int pic_snprintf(char *buf, size_t sz, const char *fmt, ...)
{
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = pic_vsnprintf(buf, sz, fmt, ap);
    va_end(ap);
    return r;
}
