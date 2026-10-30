/* Application-owned completion of two definitions missing from the pinned
 * upstream USIG Makefile. No trusted promotion or permissive undefined-call list.
 * Neither helper is reached by the five USIG ECALLs; full source units are kept.
 * crypto_verify_32 is the public-domain DJB algorithm (sk-sgx upstream/verify.c).
 * randombytes uses the existing SGX random API, with terminal failure. */
#include "edd25519/crypto_api.h"
#include <sgx_trts.h>
#include <stdlib.h>

void randombytes(unsigned char *dst, unsigned long long length)
{
    if (length && sgx_read_rand(dst, (size_t)length) != SGX_SUCCESS) abort();
}

int crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    unsigned differentbits = 0;
    for (unsigned i = 0; i < 32; ++i) differentbits |= x[i] ^ y[i];
    return (1 & ((differentbits - 1) >> 8)) - 1;
}
