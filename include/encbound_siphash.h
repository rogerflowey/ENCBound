/*
 * ENCBound restart - SipHash-2-4 and the fixed six-byte MAC input.
 *
 * Algorithm: SipHash-2-4 by Aumasson and Bernstein (public domain reference).
 * Independently implemented here; known-answer vectors in tests/siphash_test.c.
 */

#ifndef ENCBOUND_SIPHASH_H
#define ENCBOUND_SIPHASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t encbound_siphash24(uint64_t k0, uint64_t k1, const void *input,
                            size_t len);

/* SipHash-2-4 over exactly six bytes (no padding read beyond the six). */
uint64_t encbound_siphash24_fixed6(uint64_t k0, uint64_t k1,
                                   const uint8_t input[6]);

#endif /* ENCBOUND_SIPHASH_H */
