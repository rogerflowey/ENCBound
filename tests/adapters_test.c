/*
 * ENCBound restart - native tests for the step 5 checked library adapters.
 *
 * Built twice (MAC27 and RADIX_ONLY). The fake platform maps real memory at
 * enclave_base, so checked raw addresses are dereferenceable.
 */

#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encbound_common.h"
#include "encbound_runtime.h"

#include "fake_platform.h"
#include "test_harness.h"

#define KEY0 0x0706050403020100ull
#define KEY1 0x0f0e0d0c0b0a0908ull

#define EXPECT_ABORT(code, stmt)                                               \
    do {                                                                       \
        fake_abort_active = 1;                                                 \
        if (setjmp(fake_abort_env) == 0) {                                     \
            stmt;                                                              \
            g_checks++;                                                        \
            g_failures++;                                                      \
            printf("FAIL %s:%d: expected abort %d\n", __FILE__, __LINE__,      \
                   (code));                                                    \
        } else {                                                               \
            CHECK_EQ(fake_abort_code, (code));                                 \
        }                                                                      \
        fake_abort_active = 0;                                                 \
    } while (0)

static unsigned char *raw_of(void *cap, size_t n, int kind)
{
    return (unsigned char *)encbound_require((uintptr_t)cap, n, kind);
}

static void test_memcpy(void)
{
    void *dst = encbound_malloc(32);
    void *src = encbound_malloc(32);
    unsigned char *d;
    unsigned char *s;

    CHECK(dst != NULL && src != NULL);
    s = raw_of(src, 6, ENCBOUND_ACCESS_WRITE);
    memcpy(s, "hello", 6);

    CHECK_EQ(encbound_memcpy(dst, src, 6), dst);
    CHECK_EQ(encbound_memcmp(dst, src, 6), 0);
    d = raw_of(dst, 6, ENCBOUND_ACCESS_READ);
    CHECK(memcmp(d, "hello", 6) == 0);

    /* Zero length is a no-op and returns the destination capability. */
    CHECK_EQ(encbound_memcpy(dst, src, 0), dst);

    /* Source as an interior pointer with enough remaining extent. */
    CHECK_EQ(encbound_memcpy(dst, (char *)src + 1, 4), dst);
    d = raw_of(dst, 4, ENCBOUND_ACCESS_READ);
    CHECK(memcmp(d, "ello", 4) == 0);

    /* Destination has insufficient remaining extent: rejected. */
    EXPECT_ABORT(ENCBOUND_ERR_RANGE,
                 encbound_memcpy((char *)dst + 30, src, 4));
}

static void test_memset_memmove(void)
{
    void *buf = encbound_malloc(32);
    unsigned char *p;

    CHECK(buf != NULL);
    CHECK_EQ(encbound_memset(buf, 0xab, 8), buf);
    p = raw_of(buf, 8, ENCBOUND_ACCESS_READ);
    CHECK(p[0] == 0xab && p[7] == 0xab);

    CHECK_EQ(encbound_memmove((char *)buf + 8, buf, 8), (char *)buf + 8);
    p = raw_of((char *)buf + 8, 8, ENCBOUND_ACCESS_READ);
    CHECK(p[0] == 0xab && p[7] == 0xab);

    CHECK_EQ(encbound_memset(buf, 0, 0), buf); /* no-op */

    /* Overrunning the slot is rejected. */
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, encbound_memset((char *)buf + 24, 1, 16));
}

static void test_memcmp(void)
{
    void *a = encbound_malloc(32);
    void *b = encbound_malloc(32);

    CHECK(a != NULL && b != NULL);
    encbound_memset(a, 0x11, 8);
    encbound_memset(b, 0x11, 8);
    CHECK_EQ(encbound_memcmp(a, b, 8), 0);
    encbound_memset(b, 0x22, 1);
    CHECK(encbound_memcmp(a, b, 8) < 0);
    CHECK_EQ(encbound_memcmp(a, b, 0), 0);
}

static void test_strings(void)
{
    void *buf = encbound_malloc(32);
    void *other = encbound_malloc(32);
    unsigned char *p;

    CHECK(buf != NULL && other != NULL);
    p = raw_of(buf, 6, ENCBOUND_ACCESS_WRITE);
    memcpy(p, "abc", 4);
    p = raw_of(other, 6, ENCBOUND_ACCESS_WRITE);
    memcpy(p, "abd", 4);

    CHECK_EQ(encbound_strlen(buf), 3);
    CHECK_EQ(encbound_strnlen(buf, 2), 2);
    CHECK_EQ(encbound_strnlen(buf, 10), 3);
    CHECK_EQ(encbound_strcmp(buf, buf), 0);
    CHECK(encbound_strcmp(buf, other) < 0);

    /* Interior pointer preserves authority and reduces remaining extent. */
    CHECK_EQ(encbound_strlen((char *)buf + 1), 2);

    /* strncpy copies and pads with NUL. */
    CHECK_EQ(encbound_strncpy(other, buf, 6), other);
    p = raw_of(other, 6, ENCBOUND_ACCESS_READ);
    CHECK(memcmp(p, "abc\0\0\0", 6) == 0);
}

static void test_string_bounds(void)
{
    void *buf = encbound_malloc(32);
    unsigned char *p;
    size_t i;

    CHECK(buf != NULL);
    p = raw_of(buf, 32, ENCBOUND_ACCESS_WRITE);
    for (i = 0; i < 32; ++i) {
        p[i] = 'x';
    }
    /* No terminator within the validated slot extent: rejected, not over-read. */
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, (void)encbound_strlen(buf));
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, (void)encbound_strcmp(buf, buf));

    /* strncpy whose source extent ends before a terminator and before n. */
    EXPECT_ABORT(ENCBOUND_ERR_RANGE,
                 encbound_strncpy(encbound_malloc(64), buf, 40));

    /* A terminator in the final readable byte is sufficient even when the
       destination needs additional padding. Also exercise an interior source. */
    {
        void *dst = encbound_malloc(64);
        unsigned char *d = raw_of(dst, 64, ENCBOUND_ACCESS_WRITE);
        p[31] = '\0';
        memset(d, 0xa5, 64);
        CHECK_EQ(encbound_strncpy(dst, buf, 40), dst);
        CHECK(memcmp(d, p, 32) == 0);
        CHECK(memcmp(d + 32, "\0\0\0\0\0\0\0\0", 8) == 0);
        CHECK_EQ(d[40], 0xa5);
        CHECK_EQ(encbound_strncpy(dst, (char *)buf + 31, 40), dst);
        for (i = 0; i < 40; ++i) {
            if (d[i] != 0) break;
        }
        CHECK_EQ(i, 40);
        encbound_free(dst);
    }
}

static void test_forged_and_trusted(void)
{
    void *buf = encbound_malloc(32);
    uintptr_t stripped;
    uintptr_t wrong_region;

    CHECK(buf != NULL);
    encbound_memset(buf, 0, 32);

    /* Tag/radix-stripped pointer: raw offset is not a valid COMPAT address. */
    stripped = (uintptr_t)buf & ENCBOUND_OFFSET_MASK;
    EXPECT_ABORT(ENCBOUND_ERR_POLICY, (void)encbound_strlen((char *)stripped));

    /* Same capability bits but an offset into a TRUSTED region is rejected by
       region policy before any authentication step, in both profiles. */
    wrong_region = ((uintptr_t)buf & ~ENCBOUND_OFFSET_MASK) | 0x300000ull;
    EXPECT_ABORT(ENCBOUND_ERR_POLICY,
                 (void)encbound_strlen((char *)wrong_region));

#ifdef ENCBOUND_MAC27
    /* A larger radix keeps the offset in the PROTECTED heap but changes the
       authenticated slot base, so MAC27 rejects it. */
    {
        uintptr_t forged = (uintptr_t)buf + (1ull << ENCBOUND_RADIX_SHIFT);
        EXPECT_ABORT(ENCBOUND_ERR_TAG, (void)encbound_strlen((char *)forged));
    }
#endif
}

static void test_strncat(void)
{
    char *dst = encbound_malloc(32);
    char *src = encbound_malloc(32);
    char *d = (char *)raw_of(dst, 32, ENCBOUND_ACCESS_WRITE);
    char *s = (char *)raw_of(src, 32, ENCBOUND_ACCESS_WRITE);
    char reference[32] = "pre";

    strcpy(d, "pre");
    strcpy(s, "abcdef");
    strncat(reference, s, 3);
    CHECK_EQ(encbound_strncat(dst, src, 3), dst);
    CHECK(strcmp(d, reference) == 0);
    CHECK_EQ(encbound_strncat(dst + 3, src + 4, 99), dst + 3);
    CHECK(strcmp(d, "preabcef") == 0);
    CHECK_EQ(encbound_strncat(dst, NULL, 0), dst);
    CHECK(strcmp(d, "preabcef") == 0);

    /* Exactly n readable source bytes need no terminator. */
    memset(s, 'x', 32);
    d[0] = 0;
    CHECK_EQ(encbound_strncat(dst, src + 30, 2), dst);
    CHECK(strcmp(d, "xx") == 0);
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, encbound_strncat(dst, src + 30, 3));
    CHECK(strcmp(d, "xx") == 0);

    /* One byte left for the terminator: exact fit, then failure without writes. */
    memset(d, 'a', 30);
    d[30] = 0;
    d[31] = '!';
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, encbound_strncat(dst, src, 2));
    CHECK(d[30] == 0 && d[31] == '!');
    CHECK_EQ(encbound_strncat(dst, src, 1), dst);
    CHECK(d[30] == 'x' && d[31] == 0);
    memset(d, 'a', 32);
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, encbound_strncat(dst, src, 0));
    CHECK_EQ(d[31], 'a');
    encbound_free(dst);
    encbound_free(src);
}

static void test_snprintf_string(void)
{
    char *dst = encbound_malloc(32);
    char *src = encbound_malloc(32);
    char *fmt = encbound_malloc(16);
    char *d = (char *)raw_of(dst, 32, ENCBOUND_ACCESS_WRITE);
    char *s = (char *)raw_of(src, 32, ENCBOUND_ACCESS_WRITE);
    char *f = (char *)raw_of(fmt, 16, ENCBOUND_ACCESS_WRITE);
    char reference[32];
    size_t n;

    strcpy(f, "%s");
    strcpy(s, "abcdef");
    for (n = 0; n <= 10; ++n) {
        memset(d, '!', 32);
        memset(reference, '!', 32);
        CHECK_EQ(encbound_snprintf_string(dst, n, fmt, src),
                 snprintf(reference, n, "%s", s));
        CHECK(memcmp(d, reference, 32) == 0);
    }
    CHECK_EQ(encbound_snprintf_string(NULL, 0, fmt, src), 6);
    CHECK_EQ(encbound_snprintf_string(dst + 28, 4, fmt, src + 3), 3);
    CHECK(memcmp(d + 28, "def", 4) == 0);
    /* A large limit does not require touching bytes past the actual output. */
    CHECK_EQ(encbound_snprintf_string(dst + 28, SIZE_MAX, fmt, src + 3), 3);
    strcpy(s, "");
    CHECK_EQ(encbound_snprintf_string(dst + 31, 2, fmt, src), 0);
    CHECK_EQ(d[31], 0);
    strcpy(s, "abcdef");
    memset(d, '!', 32);
    EXPECT_ABORT(ENCBOUND_ERR_RANGE,
                 encbound_snprintf_string(dst + 28, 5, fmt, src));
    CHECK(memcmp(d + 28, "!!!!", 4) == 0);
    /* Full source length must be established even when no output is requested. */
    memset(s, 'x', 32);
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, encbound_snprintf_string(dst, 1, fmt, src));
    EXPECT_ABORT(ENCBOUND_ERR_RANGE, encbound_snprintf_string(NULL, 0, fmt, src));
    CHECK_EQ(d[0], '!');
    s[31] = 0;
    CHECK_EQ(encbound_snprintf_string(dst, 32, fmt, src), 31);
    CHECK(memcmp(d, s, 32) == 0);
    strcpy(f, "%n");
    EXPECT_ABORT(ENCBOUND_ERR_POLICY, encbound_snprintf_string(dst, 32, fmt, src));
    EXPECT_ABORT(ENCBOUND_ERR_RANGE,
                 encbound_snprintf_string(dst, 32, fmt + 14, src));
    encbound_free(dst);
    encbound_free(src);
    encbound_free(fmt);
}

static void test_new_adapter_authority(void)
{
    char *dst = encbound_malloc(32);
    char *src = encbound_malloc(32);
    char *fmt = encbound_malloc(16);
    /* An untagged raw enclave address into PROTECTED memory is forbidden.
       A low offset alone is outside the enclave in the fake platform and is
       intentionally accepted by fixed-width checks as a host address. */
    uintptr_t stripped = (uintptr_t)raw_of(src, 1, ENCBOUND_ACCESS_READ);
    uintptr_t trusted = ((uintptr_t)src & ~ENCBOUND_OFFSET_MASK) | 0x300000ull;
    uintptr_t invalid[3] = {stripped, trusted, 0};
    int codes[3] = {ENCBOUND_ERR_POLICY, ENCBOUND_ERR_POLICY, ENCBOUND_ERR_TAG};
    unsigned count = 2;
    unsigned i;

    memcpy(raw_of(src, 4, ENCBOUND_ACCESS_WRITE), "abc", 4);
    memcpy(raw_of(fmt, 3, ENCBOUND_ACCESS_WRITE), "%s", 3);
    encbound_memset(dst, 0, 32);
#ifdef ENCBOUND_MAC27
    invalid[2] = (uintptr_t)src ^ (1ull << ENCBOUND_TAG_SHIFT);
    count = 3;
#endif
    for (i = 0; i < count; ++i) {
        char *bad = (char *)invalid[i];
        EXPECT_ABORT(codes[i], encbound_strncat(dst, bad, 1));
        EXPECT_ABORT(codes[i], encbound_strncat(bad, src, 1));
        EXPECT_ABORT(codes[i], encbound_snprintf_string(dst, 4, fmt, bad));
        EXPECT_ABORT(codes[i], encbound_snprintf_string(bad, 4, fmt, src));
        EXPECT_ABORT(codes[i], encbound_snprintf_string(dst, 4, bad, src));
        CHECK_EQ(raw_of(dst, 1, ENCBOUND_ACCESS_READ)[0], 0);
    }
    encbound_free(dst);
    encbound_free(src);
    encbound_free(fmt);
}

int main(void)
{
    CHECK_EQ(encbound_runtime_init_with_key(KEY0, KEY1), ENCBOUND_OK);
    CHECK(encbound_runtime_ready());

    test_memcpy();
    test_memset_memmove();
    test_memcmp();
    test_strings();
    test_string_bounds();
    test_forged_and_trusted();
    test_strncat();
    test_snprintf_string();
    test_new_adapter_authority();

    return TEST_SUMMARY("adapters_test");
}
