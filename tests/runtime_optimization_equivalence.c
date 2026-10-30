/* Optimization regression: generic vs fixed-six-byte SipHash and a stable
 * valid/malformed capability corpus. Compare the transcript across O0 separate,
 * O2 separate and O2 fused builds; runtime_test supplies independent policy,
 * geometry, stack and forgery expectations. No timing or deployment keys. */
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include "encbound_common.h"
#include "encbound_runtime.h"
#include "encbound_siphash.h"
#include "encbound_internal.h"

static uint64_t state = UINT64_C(0xa68f492173bcde01);
static uint64_t next(void)
{
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

int main(void)
{
    const uint64_t k0 = UINT64_C(0x0706050403020100);
    const uint64_t k1 = UINT64_C(0x0f0e0d0c0b0a0908);
    uint64_t digest = UINT64_C(14695981039346656037);
    unsigned accepted = 0, rejected = 0;
    assert(encbound_runtime_init_with_key(k0, k1) == ENCBOUND_OK);
    void *allocation = encbound_malloc(128);
    assert(allocation);
    for (unsigned i = 0; i < 20000; ++i) {
        uint64_t r = next(), a = next(), b = next();
        uint8_t message[6];
        for (unsigned j = 0; j < 6; ++j) message[j] = (uint8_t)(r >> (j * 8));
        assert(encbound_siphash24_fixed6(a, b, message) ==
               encbound_siphash24(a, b, message, 6));
        assert(encbound_mac27(message[0], message[1], (uint32_t)(r >> 16)) ==
               (encbound_siphash24(k0, k1, message, 6) & ENCBOUND_TAG_MASK));
        uintptr_t cap;
        switch (i % 6) {
        case 0: cap = (uintptr_t)allocation + (r & 255); break;
        case 1: cap = (uintptr_t)allocation ^ (UINT64_C(1) << (r % 64)); break;
        case 2: cap = r; break;
        case 3: cap = encbound_base() + (r & 0x1ffffff); break;
        case 4: cap = (UINT64_C(1) << 47) - (r & 255); break;
        default: cap = 0; break;
        }
        const size_t widths[] = {0, 1, 8, 16, 128, 129, SIZE_MAX};
        size_t width = widths[a % 7];
        int kind = (int)(b % 5);
        uintptr_t raw = UINT64_C(0xfedcba9876543210);
        int rc = encbound_check(cap, width, kind, &raw);
        if (rc == ENCBOUND_OK) {
            ++accepted;
            /* The fake enclave is an ASLR-placed buffer. Compare enclave
             * offsets, retaining absolute values for accepted host pointers. */
            if (raw >= encbound_base() && raw - encbound_base() < 0x4000000)
                raw -= encbound_base();
        }
        else {
            ++rejected;
            assert(raw == UINT64_C(0xfedcba9876543210));
        }
        digest = (digest ^ (uint64_t)rc) * UINT64_C(1099511628211);
        digest = (digest ^ raw) * UINT64_C(1099511628211);
    }
    assert(accepted && rejected);
    encbound_free(allocation);
    printf("corpus=20000 accepted=%u rejected=%u digest=%016" PRIx64 "\n",
           accepted, rejected, digest);
    return 0;
}
