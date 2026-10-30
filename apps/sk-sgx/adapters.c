/*
 * Checked trusted adapters for the pinned mfriedl/sk-sgx enclave.
 *
 * The upstream enclave uses a small set of Intel tlibc/SGX services directly
 * from application code.  These adapters keep the application ABI unchanged:
 * every application pointer is validated as an ENCBound capability before a
 * raw SDK routine sees the decoded address.  The sealing adapters are reused
 * from wrappers/sdk_adapters.c; this file covers the sk-sgx-specific calls.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sgx_defs.h>
#include <sgx_tseal.h>
#include <sgx_trts.h>

#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "encbound_adapters.h"
#include "adapters.h"

uint32_t encbound_sk_rand(unsigned char *buf, size_t len)
{
    uintptr_t raw;

    if (len == 0)
        return SGX_SUCCESS;
    raw = encbound_require((uintptr_t)buf, len, ENCBOUND_ACCESS_WRITE);
    return sgx_read_rand((unsigned char *)raw, len);
}

uint32_t encbound_sk_calc_sealed_data_size(uint32_t additional,
                                           uint32_t plaintext)
{
    return sgx_calc_sealed_data_size(additional, plaintext);
}

uint32_t encbound_sk_get_encrypt_txt_len(const sgx_sealed_data_t *sealed)
{
    uintptr_t raw;
    size_t remaining;
    int rc;

    if (sealed == NULL)
        return UINT32_MAX;
    rc = encbound_check_extent((uintptr_t)sealed, &raw, &remaining);
    if (rc != ENCBOUND_OK || remaining < sizeof(*sealed))
        encbound_abort(rc == ENCBOUND_OK ? ENCBOUND_ERR_RANGE : rc);
    raw = encbound_require((uintptr_t)sealed, sizeof(*sealed), ENCBOUND_ACCESS_READ);
    return sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)raw);
}

uint32_t encbound_sk_get_add_mac_txt_len(const sgx_sealed_data_t *sealed)
{
    uintptr_t raw;
    size_t remaining;
    int rc;

    if (sealed == NULL)
        return UINT32_MAX;
    rc = encbound_check_extent((uintptr_t)sealed, &raw, &remaining);
    if (rc != ENCBOUND_OK || remaining < sizeof(*sealed))
        encbound_abort(rc == ENCBOUND_OK ? ENCBOUND_ERR_RANGE : rc);
    raw = encbound_require((uintptr_t)sealed, sizeof(*sealed), ENCBOUND_ACCESS_READ);
    return sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)raw);
}

int encbound_sk_consttime_memequal(const void *a, const void *b, size_t len)
{
    uintptr_t ra = 0;
    uintptr_t rb = 0;

    if (len != 0) {
        ra = encbound_require((uintptr_t)a, len, ENCBOUND_ACCESS_READ);
        rb = encbound_require((uintptr_t)b, len, ENCBOUND_ACCESS_READ);
    }
    return consttime_memequal((const void *)ra, (const void *)rb, len);
}

int encbound_sk_memset_s(void *dst, size_t capacity, int c, size_t count)
{
    size_t touched = count < capacity ? count : capacity;
    unsigned char empty;
    uintptr_t raw;

    if (dst == NULL)
        return memset_s(NULL, capacity, c, count);
    raw = touched ? encbound_require((uintptr_t)dst, touched, ENCBOUND_ACCESS_WRITE)
                  : (uintptr_t)&empty;
    return memset_s((void *)raw, capacity, c, count);
}

/* Preserve the SDK's zero-length AAD semantics for the empty application name.
 * The wallet adapter intentionally rejects unused non-null optional arguments;
 * sk-sgx always supplies the application pointer and AAD length cell. */
sgx_status_t encbound_sk_seal_data(uint32_t alen, const uint8_t *aad,
    uint32_t len, const uint8_t *text, uint32_t size, sgx_sealed_data_t *sealed)
{
    return encbound_sgx_seal_data(alen, alen ? aad : NULL, len, text, size, sealed);
}

sgx_status_t encbound_sk_unseal_data(const sgx_sealed_data_t *sealed,
    uint8_t *aad, uint32_t *alen, uint8_t *text, uint32_t *len)
{
    uint32_t actual = encbound_sk_get_add_mac_txt_len(sealed);

    if (actual != 0)
        return encbound_sgx_unseal_data(sealed, aad, alen, text, len);
    /* The pinned SDK reads this capacity even for empty AAD, then writes zero
     * on success. Validate that application cell before using a private scalar. */
    uintptr_t cell = encbound_require((uintptr_t)alen, sizeof(*alen), ENCBOUND_ACCESS_READWRITE);
    sgx_status_t status = encbound_sgx_unseal_data(sealed, NULL, NULL, text, len);
    if (status == SGX_SUCCESS)
        *(uint32_t *)cell = 0;
    return status;
}
