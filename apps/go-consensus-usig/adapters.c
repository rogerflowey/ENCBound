/* Trusted USIG SDK adapters. Reuses the opaque-token pattern in
 * apps/sgx-enclave-protocol/adapters.c. See CONTRACTS.md for exact ranges.
 * SDK pointers remain private; application data is checked before every call. */
#include <stdint.h>
#include <stddef.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include "encbound_runtime.h"

#define USIG_ECC_SLOTS 4
static sgx_ecc_state_handle_t contexts[USIG_ECC_SLOTS];

static unsigned handle_index(sgx_ecc_state_handle_t handle)
{
    uintptr_t id = (uintptr_t)handle;
    return id >= 1 && id <= USIG_ECC_SLOTS ? (unsigned)id : 0;
}

sgx_status_t encbound_usig_ecc_open(sgx_ecc_state_handle_t *handle)
{
    if (!handle) return SGX_ERROR_INVALID_PARAMETER;
    uintptr_t dst = encbound_require((uintptr_t)handle, sizeof(*handle), ENCBOUND_ACCESS_WRITE);
    unsigned i;
    for (i = 0; i < USIG_ECC_SLOTS && contexts[i]; ++i) {}
    if (i == USIG_ECC_SLOTS) return SGX_ERROR_OUT_OF_MEMORY;
    sgx_ecc_state_handle_t real = NULL;
    sgx_status_t st = sgx_ecc256_open_context(&real);
    if (st == SGX_SUCCESS) {
        contexts[i] = real;
        *(sgx_ecc_state_handle_t *)dst = (sgx_ecc_state_handle_t)(uintptr_t)(i + 1);
    }
    return st;
}

sgx_status_t encbound_usig_ecc_close(sgx_ecc_state_handle_t handle)
{
    unsigned i = handle_index(handle);
    if (!i || !contexts[i - 1]) return SGX_ERROR_INVALID_PARAMETER;
    sgx_status_t st = sgx_ecc256_close_context(contexts[i - 1]);
    if (st == SGX_SUCCESS) contexts[i - 1] = NULL;
    return st;
}

sgx_status_t encbound_usig_ecdsa_sign(const uint8_t *data, uint32_t length,
    const sgx_ec256_private_t *key, sgx_ec256_signature_t *sig, sgx_ecc_state_handle_t handle)
{
    unsigned i = handle_index(handle);
    if (!i || !contexts[i - 1] || !data || !length || !key || !sig)
        return SGX_ERROR_INVALID_PARAMETER;
    uintptr_t d = encbound_require((uintptr_t)data, length, ENCBOUND_ACCESS_READ);
    uintptr_t k = encbound_require((uintptr_t)key, sizeof(*key), ENCBOUND_ACCESS_READ);
    uintptr_t s = encbound_require((uintptr_t)sig, sizeof(*sig), ENCBOUND_ACCESS_WRITE);
    return sgx_ecdsa_sign((const uint8_t *)d, length, (const sgx_ec256_private_t *)k,
        (sgx_ec256_signature_t *)s, contexts[i - 1]);
}

sgx_status_t encbound_usig_hmac(const unsigned char *src, int src_len,
    const unsigned char *key, int key_len, unsigned char *mac, int mac_len)
{
    /* Pinned IPP SDK rejects these without accessing caller buffers. Positive
     * mac_len may also be an SDK error: its error cleanup writes mac_len bytes. */
    if (!src || !key || !mac || src_len <= 0 || key_len <= 0 || mac_len <= 0)
        return SGX_ERROR_INVALID_PARAMETER;
    uintptr_t s = encbound_require((uintptr_t)src, (size_t)src_len, ENCBOUND_ACCESS_READ);
    uintptr_t k = encbound_require((uintptr_t)key, (size_t)key_len, ENCBOUND_ACCESS_READ);
    uintptr_t m = encbound_require((uintptr_t)mac, (size_t)mac_len, ENCBOUND_ACCESS_WRITE);
    return sgx_hmac_sha256_msg((const unsigned char *)s, src_len,
        (const unsigned char *)k, key_len, (unsigned char *)m, mac_len);
}

sgx_status_t encbound_usig_rand(unsigned char *dst, size_t length)
{
    if (!dst || !length) return SGX_ERROR_INVALID_PARAMETER;
    uintptr_t d = encbound_require((uintptr_t)dst, length, ENCBOUND_ACCESS_WRITE);
    return sgx_read_rand((unsigned char *)d, length);
}
