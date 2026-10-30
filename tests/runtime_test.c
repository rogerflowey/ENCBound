/*
 * ENCBound restart - native runtime tests against the fake platform.
 *
 * Build twice: with and without -DENCBOUND_MAC27. Expands to the step 3
 * required-behavior table where the profile changes the expected result.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encbound_common.h"
#include "encbound_regions.h"
#include "encbound_runtime.h"
#include "encbound_siphash.h"
#include "encbound_internal.h"

#include "fake_platform.h"
#include "test_harness.h"

#define KEY0 0x0706050403020100ull
#define KEY1 0x0f0e0d0c0b0a0908ull

#define ARENA_OFF 0x1000000ull
#define STACK_OFF 0x100000ull
#define STACK_SIZE 0x100000ull
#define COMPAT_OFF 0x200000ull
#define COMPAT_SIZE 0x10000ull

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

static void test_siphash(void)
{
    CHECK_EQ(encbound_siphash24(KEY0, KEY1, "", 0), 0x726fdb47dd0e0e31ull);
    CHECK_EQ(encbound_siphash24(KEY0, KEY1, "Hello world", 11),
             0x3107336b26ce133dull);
    {
        const uint8_t input[6] = { 1, 6, 0, 0, 0, 0 };
        CHECK_EQ(encbound_siphash24_fixed6(KEY0, KEY1, input),
                 encbound_siphash24(KEY0, KEY1, input, sizeof(input)));
    }
}

static void test_access_paths(uintptr_t base)
{
    void *cap = encbound_malloc(32);
    uintptr_t raw;
    uintptr_t p;

    CHECK(cap != NULL);
    CHECK_EQ(encbound_radix_of((uintptr_t)cap), 5);
    CHECK_EQ(encbound_check((uintptr_t)cap, 32, ENCBOUND_ACCESS_READWRITE,
                            &raw),
             ENCBOUND_OK);
    CHECK(raw >= base + ARENA_OFF && raw < base + ARENA_OFF + 0x1000000ull);
    memset((void *)raw, 0x5a, 32);

    /* Last byte valid; one past and straddle rejected. */
    CHECK_EQ(encbound_check((uintptr_t)cap + 31, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);
    CHECK_EQ(encbound_check((uintptr_t)cap + 31, 2, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_RANGE);
    CHECK_EQ(encbound_check((uintptr_t)cap + 28, 8, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_RANGE);
    CHECK_EQ(encbound_check((uintptr_t)cap, 0, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_RANGE);
    encbound_free(cap);
}

static void test_padding_and_next_slot(uintptr_t base)
{
    void *cap = encbound_malloc(24); /* rounded to a 32-byte slot */
    uintptr_t p;
    (void)base;

    CHECK(cap != NULL);
    CHECK_EQ(encbound_radix_of((uintptr_t)cap), 5);
    /* Padding within the rounded slot is accessible: declared limitation. */
    CHECK_EQ(encbound_check((uintptr_t)cap + 24, 8, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);
    /* Moving the offset to the next slot base keeps the old tag. */
#ifdef ENCBOUND_MAC27
    CHECK_EQ(encbound_check((uintptr_t)cap + 32, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_TAG);
#else
    CHECK_EQ(encbound_check((uintptr_t)cap + 32, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);
#endif
    encbound_free(cap);
}

static void test_tag_and_radix_forgery(void)
{
    void *cap = encbound_malloc(32);
    uintptr_t forged;
    uintptr_t p;

    CHECK(cap != NULL);
    forged = (uintptr_t)cap ^ (1ull << ENCBOUND_TAG_SHIFT); /* flip tag bit */
#ifdef ENCBOUND_MAC27
    CHECK_EQ(encbound_check(forged, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_TAG);
#else
    CHECK_EQ(encbound_check(forged, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);
#endif

    /* Claim a larger containing slot by changing the radix. */
    forged = ((uintptr_t)cap & ~(0x1full << ENCBOUND_RADIX_SHIFT)) |
             (6ull << ENCBOUND_RADIX_SHIFT);
#ifdef ENCBOUND_MAC27
    CHECK_EQ(encbound_check(forged, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_TAG);
#endif
    encbound_free(cap);
}

static void test_domain_binding(uintptr_t base)
{
    void *stack_cap = NULL;
    uintptr_t p;

    CHECK_EQ(encbound_stack_slot((void *)(base + STACK_OFF), 0x1000,
                                 &stack_cap),
             ENCBOUND_OK);
    CHECK(stack_cap != NULL);
    CHECK_EQ(encbound_check((uintptr_t)stack_cap, 0x1000, ENCBOUND_ACCESS_READ,
                            &p),
             ENCBOUND_OK);
#ifdef ENCBOUND_MAC27
    /* A heap-domain tag over the same stack slot must not authenticate. */
    {
        uintptr_t heap_tagged =
            (12ull << ENCBOUND_RADIX_SHIFT) |
            (encbound_mac27(ENCBOUND_DOMAIN_HEAP, 12, STACK_OFF)
             << ENCBOUND_TAG_SHIFT) |
            STACK_OFF;
        CHECK_EQ(encbound_check(heap_tagged, 1, ENCBOUND_ACCESS_READ, &p),
                 ENCBOUND_ERR_TAG);
    }
#endif
}

static void test_untagged_paths(uintptr_t base)
{
    uintptr_t p;
    int local = 0;

    /* Raw address into a PROTECTED or TRUSTED region is rejected by policy. */
    CHECK_EQ(encbound_check(base + ARENA_OFF, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_POLICY);
    CHECK_EQ(encbound_check(base + STACK_OFF, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_POLICY);
    CHECK_EQ(encbound_check(base + 0x300000ull, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_POLICY);

    /* A complete COMPAT range is admitted; an outside host range too. */
    CHECK_EQ(encbound_check(base + COMPAT_OFF, 16, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);
    CHECK_EQ(encbound_check((uintptr_t)&local, sizeof(local),
                            ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);

    /* Crossing the COMPAT region edge is rejected. */
    CHECK_EQ(encbound_check(base + COMPAT_OFF + COMPAT_SIZE - 8, 16,
                            ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_POLICY);

    /* Non-canonical / high address encoding is rejected. */
    CHECK_EQ(encbound_check(0x800000000000ull, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_ENCODING);

    /* NULL is not a valid object. */
    CHECK_EQ(encbound_check(0, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_ENCODING);

    /* The whole accessed range must be canonical: a range that starts just
       below 2^47 but ends at or above it is rejected, while one that ends at
       2^47 - 1 is admitted. */
    CHECK_EQ(encbound_check((0x1ull << 47) - 1, 2, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_ENCODING);
    CHECK_EQ(encbound_check(0x1ull << 47, 1, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_ENCODING);
    CHECK_EQ(encbound_check((0x1ull << 47) - 8, 8, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_OK);

    /* Zero width is still rejected on both the tagged and untagged paths. */
    CHECK_EQ(encbound_check(0x1ull, 0, ENCBOUND_ACCESS_READ, &p),
             ENCBOUND_ERR_RANGE);
}

static void test_bad_free(void)
{
    void *cap = encbound_malloc(64);
    void *stack_cap = NULL;

    CHECK(cap != NULL);
    CHECK_EQ(encbound_free_checked((void *)((uintptr_t)cap + 1)),
             ENCBOUND_ERR_RANGE); /* interior */
#ifdef ENCBOUND_MAC27
    CHECK_EQ(encbound_free_checked(
                 (void *)((uintptr_t)cap ^ (1ull << ENCBOUND_TAG_SHIFT))),
             ENCBOUND_ERR_TAG);
#endif
    CHECK_EQ(encbound_free_checked(cap), ENCBOUND_OK);
    CHECK_EQ(encbound_free_checked(cap), ENCBOUND_ERR_OWNERSHIP); /* double */

    CHECK_EQ(encbound_stack_slot(
                 (void *)(encbound_base() + STACK_OFF), 0x1000, &stack_cap),
             ENCBOUND_OK);
    CHECK_EQ(encbound_free_checked(stack_cap), ENCBOUND_ERR_POLICY);
}

static void test_realloc_and_calloc(void)
{
    void *cap = encbound_malloc(100);
    void *big;
    uintptr_t raw;
    uint32_t *words;

    CHECK(cap != NULL);
    CHECK_EQ(encbound_check((uintptr_t)cap, 100, ENCBOUND_ACCESS_READWRITE,
                            &raw),
             ENCBOUND_OK);
    memset((void *)raw, 0x11, 100);

    /* Allocation failure preserves the old object. */
    big = encbound_realloc(cap, 0x4000000ull); /* 64 MiB > 16 MiB arena */
    CHECK(big == NULL);
    CHECK_EQ(encbound_check((uintptr_t)cap, 100, ENCBOUND_ACCESS_READ, &raw),
             ENCBOUND_OK);
    CHECK(((uint8_t *)raw)[0] == 0x11 && ((uint8_t *)raw)[99] == 0x11);

    /* Successful realloc moves and preserves min(old,new). */
    big = encbound_realloc(cap, 200);
    CHECK(big != NULL);
    CHECK_EQ(encbound_check((uintptr_t)big, 100, ENCBOUND_ACCESS_READ, &raw),
             ENCBOUND_OK);
    CHECK(((uint8_t *)raw)[0] == 0x11);
    encbound_free(big);

    CHECK(encbound_calloc((size_t)-1, 2) == NULL);
    CHECK(encbound_calloc(0, 4) == NULL);
    words = (uint32_t *)encbound_calloc(8, 4);
    CHECK(words != NULL);
    CHECK_EQ(encbound_check((uintptr_t)words, 32, ENCBOUND_ACCESS_READ, &raw),
             ENCBOUND_OK);
    CHECK(((uint32_t *)raw)[0] == 0 && ((uint32_t *)raw)[7] == 0);
    encbound_free(words);
}

static void test_stack_slot(uintptr_t base)
{
    uint8_t *slot = (uint8_t *)(base + STACK_OFF);
    void *cap = NULL;
    uintptr_t raw;
    size_t i;

    memset(slot, 0xab, 0x1000);
    CHECK_EQ(encbound_stack_slot(slot, 0x1000, &cap), ENCBOUND_OK);
    for (i = 0; i < 0x1000; ++i) {
        if (slot[i] != 0) {
            break;
        }
    }
    CHECK_EQ(i, 0x1000); /* whole rounded slot cleared */
    CHECK_EQ(encbound_check((uintptr_t)cap, 0x1000, ENCBOUND_ACCESS_READ,
                            &raw),
             ENCBOUND_OK);

    CHECK_EQ(encbound_stack_slot(slot + 1, 0x1000, &cap), ENCBOUND_ERR_ALLOC);
    CHECK_EQ(encbound_stack_slot(slot, 0x1001, &cap), ENCBOUND_ERR_ALLOC);
}

static void test_exhaustion_and_reuse(void)
{
    void *caps[512];
    size_t count = 0;
    void *a;
    void *b;
    size_t i;

    while (count < 512) {
        void *cap = encbound_malloc(0x10000ull); /* 64 KiB each */
        if (cap == NULL) {
            break;
        }
        caps[count++] = cap;
    }
    CHECK(count > 0 && count < 512); /* defined exhaustion, no fallback */
    for (i = 0; i < count; ++i) {
        encbound_free(caps[i]);
    }

    a = encbound_malloc(64);
    encbound_free(a);
    b = encbound_malloc(64);
    CHECK(b != NULL);
    /* Stale capability may match the reused slot: temporal safety is deferred. */
    (void)a;
    encbound_free(b);
}

int main(void)
{
    uintptr_t base;

    CHECK_EQ(encbound_runtime_init_with_key(KEY0, KEY1), ENCBOUND_OK);
    CHECK(encbound_runtime_ready());
    base = encbound_base();

    test_siphash();
    test_access_paths(base);
    test_padding_and_next_slot(base);
    test_tag_and_radix_forgery();
    test_domain_binding(base);
    test_untagged_paths(base);
    test_bad_free();
    test_realloc_and_calloc();
    test_stack_slot(base);
    test_exhaustion_and_reuse();

    return TEST_SUMMARY("runtime_test");
}
