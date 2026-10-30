/*
 * ENCBound restart - E2 instrumented LZ4 round-trip fixture.
 *
 * A test-only application-domain unit compiled through tools/encbound-cc.sh and
 * linked only into the SDK diagnostic enclave. It drives LZ4 v1.10.0's serial
 * buffer API on three live heap buffers, so the compression context's accesses
 * and the library's read-only lookup tables all pass through compiler-inserted
 * checks. Results are reported through the trusted observer `forgery_report`.
 *
 * This exercises a genuine library workload with active heap/stack checking;
 * it is not the sgx-wallet and not a vulnerability claim.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Implemented in sdk/forgery_probe.c (trusted). */
extern int forgery_report(uint32_t index, uint64_t value);

/* LZ4 v1.10.0 entry points (apps/sgx-lz4/lz4), cross-translation-unit
 * application calls admitted by the build's admitted symbols file. */
extern int LZ4_compress_default(const char *src, char *dst, int src_size,
                                int dst_capacity);
extern int LZ4_decompress_safe(const char *src, char *dst, int compressed_size,
                               int dst_capacity);
extern int LZ4_compressBound(int input_size);

#define LZ4_PROBE_INPUT 4096

__attribute__((noinline)) static unsigned int probe_pattern(unsigned int i)
{
    /* Deterministic, partly repetitive input: exercises LZ4 match finding. */
    if ((i & 0x3fu) < 0x20u) {
        return (i >> 5) & 0xffu;
    }
    return (i * 31u) ^ (i >> 3);
}

int lz4_probe(void)
{
    unsigned char *in = malloc(LZ4_PROBE_INPUT);
    unsigned char *packed;
    unsigned char *out = malloc(LZ4_PROBE_INPUT);
    int bound;
    int packed_len;
    int out_len;
    unsigned int i;

    if (in == NULL || out == NULL) {
        return 10;
    }
    bound = LZ4_compressBound(LZ4_PROBE_INPUT);
    if (bound <= 0) {
        free(in);
        free(out);
        return 11;
    }
    packed = malloc((size_t)bound);
    if (packed == NULL) {
        free(in);
        free(out);
        return 12;
    }

    for (i = 0; i < LZ4_PROBE_INPUT; ++i) {
        in[i] = (unsigned char)probe_pattern(i);
    }

    packed_len = LZ4_compress_default((const char *)in, (char *)packed,
                                      LZ4_PROBE_INPUT, bound);
    if (packed_len <= 0) {
        free(in);
        free(packed);
        free(out);
        return 13;
    }

    out_len = LZ4_decompress_safe((const char *)packed, (char *)out, packed_len,
                                  LZ4_PROBE_INPUT);
    if (out_len != LZ4_PROBE_INPUT) {
        free(in);
        free(packed);
        free(out);
        return 14;
    }
    for (i = 0; i < LZ4_PROBE_INPUT; ++i) {
        if (out[i] != (unsigned char)probe_pattern(i)) {
            free(in);
            free(packed);
            free(out);
            return 15;
        }
    }

    forgery_report(0, (uint64_t)packed_len);
    forgery_report(1, (uint64_t)out_len);
    free(in);
    free(packed);
    free(out);
    return 0;
}
