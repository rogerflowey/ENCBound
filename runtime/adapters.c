/*
 * ENCBound restart - step 5 checked library adapters (trusted).
 *
 * Application call sites are redirected here by the compiler pass. Each adapter
 * validates complete capability ranges through the runtime before calling a raw
 * routine, and never returns or exposes a raw address. SDK-internal calls are
 * not redirected. See docs/legacy/contracts/library-adapters.md for the filled contracts.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"

void *encbound_memcpy(void *dst, const void *src, size_t n)
{
    uintptr_t d;
    uintptr_t s;

    if (n == 0) {
        return dst;
    }
    d = encbound_require((uintptr_t)dst, n, ENCBOUND_ACCESS_WRITE);
    s = encbound_require((uintptr_t)src, n, ENCBOUND_ACCESS_READ);
    memcpy((void *)d, (const void *)s, n);
    return dst;
}

void *encbound_memmove(void *dst, const void *src, size_t n)
{
    uintptr_t d;
    uintptr_t s;

    if (n == 0) {
        return dst;
    }
    d = encbound_require((uintptr_t)dst, n, ENCBOUND_ACCESS_WRITE);
    s = encbound_require((uintptr_t)src, n, ENCBOUND_ACCESS_READ);
    memmove((void *)d, (const void *)s, n);
    return dst;
}

void *encbound_memset(void *dst, int c, size_t n)
{
    uintptr_t d;

    if (n == 0) {
        return dst;
    }
    d = encbound_require((uintptr_t)dst, n, ENCBOUND_ACCESS_WRITE);
    memset((void *)d, c, n);
    return dst;
}

int encbound_memcmp(const void *a, const void *b, size_t n)
{
    uintptr_t ra;
    uintptr_t rb;

    if (n == 0) {
        return 0;
    }
    ra = encbound_require((uintptr_t)a, n, ENCBOUND_ACCESS_READ);
    rb = encbound_require((uintptr_t)b, n, ENCBOUND_ACCESS_READ);
    return memcmp((const void *)ra, (const void *)rb, n);
}

size_t encbound_strlen(const char *s)
{
    uintptr_t raw;
    size_t remaining;
    const unsigned char *p;
    size_t i;
    int rc = encbound_check_extent((uintptr_t)s, &raw, &remaining);

    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
    p = (const unsigned char *)raw;
    for (i = 0; i < remaining; ++i) {
        if (p[i] == '\0') {
            return i;
        }
    }
    /* No terminator inside the validated extent. */
    encbound_abort(ENCBOUND_ERR_RANGE);
}

size_t encbound_strnlen(const char *s, size_t maxlen)
{
    uintptr_t raw;
    size_t remaining;
    const unsigned char *p;
    size_t bound;
    size_t i;
    int rc = encbound_check_extent((uintptr_t)s, &raw, &remaining);

    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
    p = (const unsigned char *)raw;
    bound = remaining < maxlen ? remaining : maxlen;
    for (i = 0; i < bound; ++i) {
        if (p[i] == '\0') {
            return i;
        }
    }
    /* A terminator before maxlen was required but the extent ended first. */
    if (remaining < maxlen) {
        encbound_abort(ENCBOUND_ERR_RANGE);
    }
    return maxlen;
}

int encbound_strcmp(const char *a, const char *b)
{
    uintptr_t raw_a;
    uintptr_t raw_b;
    size_t remaining_a;
    size_t remaining_b;
    const unsigned char *pa;
    const unsigned char *pb;
    size_t bound;
    size_t i;
    int rc_a = encbound_check_extent((uintptr_t)a, &raw_a, &remaining_a);
    int rc_b = encbound_check_extent((uintptr_t)b, &raw_b, &remaining_b);

    if (rc_a != ENCBOUND_OK) {
        encbound_abort(rc_a);
    }
    if (rc_b != ENCBOUND_OK) {
        encbound_abort(rc_b);
    }
    pa = (const unsigned char *)raw_a;
    pb = (const unsigned char *)raw_b;
    bound = remaining_a < remaining_b ? remaining_a : remaining_b;
    for (i = 0; i < bound; ++i) {
        if (pa[i] != pb[i]) {
            return (int)pa[i] - (int)pb[i];
        }
        if (pa[i] == '\0') {
            return 0;
        }
    }
    /* Neither string terminated inside the shorter validated extent. */
    encbound_abort(ENCBOUND_ERR_RANGE);
}

char *encbound_strncpy(char *dst, const char *src, size_t n)
{
    uintptr_t raw_dst;
    uintptr_t raw_src;
    size_t remaining_src;
    unsigned char *q;
    const unsigned char *p;
    size_t i;
    int rc;
    int terminated = 0;

    if (n == 0) {
        return dst;
    }
    raw_dst = encbound_require((uintptr_t)dst, n, ENCBOUND_ACCESS_WRITE);
    rc = encbound_check_extent((uintptr_t)src, &raw_src, &remaining_src);
    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
    q = (unsigned char *)raw_dst;
    p = (const unsigned char *)raw_src;
    i = 0;
    while (i < n && i < remaining_src) {
        q[i] = p[i];
        if (p[i] == '\0') {
            terminated = 1;
            ++i;
            break;
        }
        ++i;
    }
    if (!terminated && i < n && i == remaining_src) {
        /* Source extent ended before a terminator was found, yet padding is
           required: the terminator is not provably inside the extent. */
        encbound_abort(ENCBOUND_ERR_RANGE);
    }
    while (i < n) {
        q[i++] = '\0';
    }
    return dst;
}

char *encbound_strncat(char *dst, const char *src, size_t n)
{
    size_t prefix = encbound_strlen(dst);
    size_t count = n == 0 ? 0 : encbound_strnlen(src, n);
    uintptr_t d;
    uintptr_t s = 0;

    if (prefix == SIZE_MAX || count > SIZE_MAX - prefix - 1) {
        encbound_abort(ENCBOUND_ERR_RANGE);
    }
    /* Validate from the original capability, before deriving the append
       address. Otherwise crossing a slot could change the inferred base. */
    d = encbound_require((uintptr_t)dst, prefix + count + 1,
                        ENCBOUND_ACCESS_WRITE);
    if (count != 0) {
        s = encbound_require((uintptr_t)src, count, ENCBOUND_ACCESS_READ);
        memcpy((char *)d + prefix, (const void *)s, count);
    }
    ((char *)d)[prefix + count] = '\0';
    return dst;
}

/* Fixed ABI for the compiler-admitted snprintf(dst, n, "%s", src) subset.
   No raw variadic callee receives application capabilities. */
int encbound_snprintf_string(char *dst, size_t n, const char *format,
                            const char *src)
{
    const char *f = (const char *)encbound_require((uintptr_t)format, 3,
                                                 ENCBOUND_ACCESS_READ);
    size_t length;
    size_t count;
    uintptr_t d;
    uintptr_t s;

    if (f[0] != '%' || f[1] != 's' || f[2] != '\0') {
        encbound_abort(ENCBOUND_ERR_POLICY);
    }
    /* The return value counts the full source even when output is truncated. */
    length = encbound_strlen(src);
    if (length > INT_MAX) {
        /* Outside this adapter's supported, int-representable result domain. */
        encbound_abort(ENCBOUND_ERR_RANGE);
    }
    if (n == 0) {
        return (int)length;
    }
    count = length < n - 1 ? length : n - 1;
    d = encbound_require((uintptr_t)dst, count + 1, ENCBOUND_ACCESS_WRITE);
    if (count != 0) {
        s = encbound_require((uintptr_t)src, count, ENCBOUND_ACCESS_READ);
        memcpy((void *)d, (const void *)s, count);
    }
    ((char *)d)[count] = '\0';
    return (int)length;
}
