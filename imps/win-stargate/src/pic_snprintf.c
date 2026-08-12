/*
 * Minimal _snprintf for -nostdlib PIC shellcode (formats used by tempest_c2).
 */
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>

static void emit_dec_ull(unsigned long long v, char *out, size_t osz)
{
    char tmp[24];
    int i = 0;
    if (osz == 0) return;
    if (v == 0) {
        out[0] = '0';
        out[1] = 0;
        return;
    }
    while (v && i < (int)sizeof(tmp)) {
        tmp[i++] = (char)('0' + (v % 10ULL));
        v /= 10ULL;
    }
    size_t j = 0;
    while (i > 0 && j + 1 < osz) out[j++] = tmp[--i];
    out[j] = 0;
}

static void emit_dec_ll(long long v, char *out, size_t osz)
{
    unsigned long long u;
    if (osz == 0) return;
    if (v < 0) {
        out[0] = '-';
        if (v == LLONG_MIN) u = (unsigned long long)LLONG_MAX + 1ULL;
        else u = (unsigned long long)(-v);
        emit_dec_ull(u, out + 1, osz > 1 ? osz - 1 : 0);
        return;
    }
    emit_dec_ull((unsigned long long)v, out, osz);
}

int pic_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap)
{
    size_t pos = 0;
    const char *f = fmt;

    if (!fmt) {
        if (buf && n) buf[0] = 0;
        return 0;
    }

    while (*f) {
        if (*f != '%') {
            if (buf && pos + 1 < n) buf[pos] = *f;
            pos++;
            f++;
            continue;
        }
        f++;
        if (*f == '%') {
            if (buf && pos + 1 < n) buf[pos] = '%';
            pos++;
            f++;
            continue;
        }
        if (*f == 's') {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s) {
                if (buf && pos + 1 < n) buf[pos] = *s;
                pos++;
                s++;
            }
            f++;
            continue;
        }
        if (*f == 'd') {
            int v = va_arg(ap, int);
            char tmp[32];
            emit_dec_ll((long long)v, tmp, sizeof tmp);
            for (const char *p = tmp; *p; p++) {
                if (buf && pos + 1 < n) buf[pos] = *p;
                pos++;
            }
            f++;
            continue;
        }
        if (*f == 'l' && f[1] == 'l' && f[2] == 'u') {
            unsigned long long v = va_arg(ap, unsigned long long);
            char tmp[40];
            emit_dec_ull(v, tmp, sizeof tmp);
            for (const char *p = tmp; *p; p++) {
                if (buf && pos + 1 < n) buf[pos] = *p;
                pos++;
            }
            f += 3;
            continue;
        }
        if (*f == 'l' && f[1] == 'u') {
            unsigned long v = va_arg(ap, unsigned long);
            char tmp[32];
            emit_dec_ull((unsigned long long)v, tmp, sizeof tmp);
            for (const char *p = tmp; *p; p++) {
                if (buf && pos + 1 < n) buf[pos] = *p;
                pos++;
            }
            f += 2;
            continue;
        }
        if (*f == 'u') {
            unsigned int v = va_arg(ap, unsigned int);
            char tmp[24];
            emit_dec_ull(v, tmp, sizeof tmp);
            for (const char *p = tmp; *p; p++) {
                if (buf && pos + 1 < n) buf[pos] = *p;
                pos++;
            }
            f++;
            continue;
        }
        if (*f == 'z' && f[1] == 'u') {
            size_t vz = va_arg(ap, size_t);
            char tmp[40];
            emit_dec_ull((unsigned long long)vz, tmp, sizeof tmp);
            for (const char *p = tmp; *p; p++) {
                if (buf && pos + 1 < n) buf[pos] = *p;
                pos++;
            }
            f += 2;
            continue;
        }
        if (buf && pos + 1 < n) buf[pos] = '?';
        pos++;
        f++;
    }

    if (buf && n) {
        if (pos >= n) buf[n - 1] = 0;
        else buf[pos] = 0;
    }
    return (int)pos;
}

int _snprintf(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = pic_vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return r;
}
