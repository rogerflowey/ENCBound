/*
 * ENCBound restart - SipHash-2-4.
 *
 * Origin: SipHash-2-4 reference algorithm (Aumasson, Bernstein). This is a
 * clean implementation written for the restart. Known-answer vectors are
 * frozen in tests/siphash_test.c and were cross-checked against OpenSSL 3.6
 * (siphash, size 8) for the empty input and "Hello world".
 */

#include "encbound_siphash.h"

static uint64_t rotl64(uint64_t x, unsigned b)
{
    return (x << b) | (x >> (64u - b));
}

#define SIPROUND()                                                             \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = rotl64(v1, 13);                                                   \
        v1 ^= v0;                                                              \
        v0 = rotl64(v0, 32);                                                   \
        v2 += v3;                                                              \
        v3 = rotl64(v3, 16);                                                   \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = rotl64(v3, 21);                                                   \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = rotl64(v1, 17);                                                   \
        v1 ^= v2;                                                              \
        v2 = rotl64(v2, 32);                                                   \
    } while (0)

static uint64_t load_le64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

uint64_t encbound_siphash24(uint64_t k0, uint64_t k1, const void *input,
                            size_t len)
{
    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *end = p + (len & ~(size_t)7);
    uint64_t v0 = 0x736f6d6570736575ull ^ k0;
    uint64_t v1 = 0x646f72616e646f6dull ^ k1;
    uint64_t v2 = 0x6c7967656e657261ull ^ k0;
    uint64_t v3 = 0x7465646279746573ull ^ k1;
    uint64_t m;

    while (p < end) {
        m = load_le64(p);
        v3 ^= m;
        SIPROUND();
        SIPROUND();
        v0 ^= m;
        p += 8;
    }

    m = (uint64_t)(len & 0xffu) << 56;
    switch (len & 7u) {
    case 7:
        m |= (uint64_t)p[6] << 48; /* fallthrough */
    case 6:
        m |= (uint64_t)p[5] << 40; /* fallthrough */
    case 5:
        m |= (uint64_t)p[4] << 32; /* fallthrough */
    case 4:
        m |= (uint64_t)p[3] << 24; /* fallthrough */
    case 3:
        m |= (uint64_t)p[2] << 16; /* fallthrough */
    case 2:
        m |= (uint64_t)p[1] << 8; /* fallthrough */
    case 1:
        m |= (uint64_t)p[0]; /* fallthrough */
    default:
        break;
    }
    v3 ^= m;
    SIPROUND();
    SIPROUND();
    v0 ^= m;
    v2 ^= 0xff;
    SIPROUND();
    SIPROUND();
    SIPROUND();
    SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}

static inline __attribute__((always_inline))
uint64_t siphash24_fixed6_inline(uint64_t k0, uint64_t k1,
                                   const uint8_t input[6])
{
    uint64_t v0 = 0x736f6d6570736575ull ^ k0;
    uint64_t v1 = 0x646f72616e646f6dull ^ k1;
    uint64_t v2 = 0x6c7967656e657261ull ^ k0;
    uint64_t v3 = 0x7465646279746573ull ^ k1;
    uint64_t m = (uint64_t)input[0] | ((uint64_t)input[1] << 8) |
                 ((uint64_t)input[2] << 16) | ((uint64_t)input[3] << 24) |
                 ((uint64_t)input[4] << 32) | ((uint64_t)input[5] << 40) |
                 (6ull << 56);

    v3 ^= m;
    SIPROUND();
    SIPROUND();
    v0 ^= m;
    v2 ^= 0xff;
    SIPROUND();
    SIPROUND();
    SIPROUND();
    SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}

/* Keep the public byte-buffer API for separate compilation and vector tests.
 * The trusted fused core calls the same inline body so its six-byte message
 * can remain in registers instead of being serialized to the stack and read
 * back by a separately compiled function. The rounds and input are unchanged.
 */
uint64_t encbound_siphash24_fixed6(uint64_t k0, uint64_t k1,
                                 const uint8_t input[6])
{
    return siphash24_fixed6_inline(k0, k1, input);
}
