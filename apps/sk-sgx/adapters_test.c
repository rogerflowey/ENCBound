/* Native adapter contracts, with the real checked runtime and recording SDK
 * stand-ins. Successful stand-ins dereference decoded pointers. These are
 * boundary tests; the SIM host separately verifies real SDK cryptography. */
#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sgx_error.h>
#include "adapters.h"
#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "fake_platform.h"
#include "test_harness.h"

static unsigned raw_calls;

#define REJECT(code, expression) do { \
    unsigned before = raw_calls; \
    fake_abort_active = 1; \
    if (setjmp(fake_abort_env) == 0) { \
        (void)(expression); CHECK(0); \
    } else { CHECK_EQ(fake_abort_code, code); } \
    fake_abort_active = 0; \
    CHECK_EQ(raw_calls, before); \
} while (0)

uint32_t sgx_read_rand(unsigned char *p, size_t n)
{
    ++raw_calls;
    memset(p, 0xa5, n);
    return SGX_SUCCESS;
}

int consttime_memequal(const void *a, const void *b, size_t n)
{
    ++raw_calls;
    return n == 0 || memcmp(a, b, n) == 0;
}

int memset_s(void *p, size_t capacity, int c, size_t count)
{
    ++raw_calls;
    if (!p) return EINVAL;
    memset(p, c, count < capacity ? count : capacity);
    return count > capacity ? EOVERFLOW : 0;
}

uint32_t sgx_calc_sealed_data_size(uint32_t a, uint32_t n)
{
    if ((uint64_t)sizeof(sgx_sealed_data_t) + a + n > UINT32_MAX)
        return UINT32_MAX;
    return sizeof(sgx_sealed_data_t) + a + n;
}

uint32_t sgx_get_encrypt_txt_len(const sgx_sealed_data_t *s)
{
    ++raw_calls;
    return s ? s->plain_text_offset : UINT32_MAX;
}

uint32_t sgx_get_add_mac_txt_len(const sgx_sealed_data_t *s)
{
    ++raw_calls;
    return s ? s->aes_data.payload_size - s->plain_text_offset : UINT32_MAX;
}

sgx_status_t sgx_seal_data(uint32_t a, const uint8_t *aad, uint32_t n,
    const uint8_t *text, uint32_t size, sgx_sealed_data_t *s)
{
    ++raw_calls;
    if (size != sgx_calc_sealed_data_size(a, n))
        return SGX_ERROR_INVALID_PARAMETER;
    CHECK(a || aad == NULL);
    memset(s, 0, size);
    s->plain_text_offset = n;
    s->aes_data.payload_size = a + n;
    if (a) memcpy(s->aes_data.payload, aad, a);
    memcpy(s->aes_data.payload + a, text, n);
    return SGX_SUCCESS;
}

sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *s, uint8_t *aad,
    uint32_t *a, uint8_t *text, uint32_t *n)
{
    ++raw_calls;
    uint32_t len = s->plain_text_offset;
    uint32_t alen = s->aes_data.payload_size - len;
    CHECK(alen || (aad == NULL && a == NULL));
    if (alen) {
        CHECK(*a >= alen);
        memcpy(aad, s->aes_data.payload, alen);
        *a = alen;
    }
    CHECK(*n >= len);
    memcpy(text, s->aes_data.payload + alen, len);
    *n = len;
    return SGX_SUCCESS;
}

static uint8_t *raw(void *p, size_t n)
{
    return (uint8_t *)encbound_require((uintptr_t)p, n, ENCBOUND_ACCESS_READWRITE);
}

int main(void)
{
    CHECK_EQ(encbound_runtime_init_with_key(0x0706050403020100ULL,
                                           0x0f0e0d0c0b0a0908ULL), ENCBOUND_OK);
    uint8_t *a = encbound_malloc(64), *b = encbound_malloc(64);
    uint8_t *plain = encbound_malloc(64);
    uint8_t *small = encbound_malloc(16);
    CHECK(a && b && small && plain);
    CHECK_EQ(encbound_sk_rand(a, 64), SGX_SUCCESS);
    CHECK(raw(a,64)[63] == 0xa5);
    CHECK_EQ(encbound_sk_rand(NULL, 0), SGX_SUCCESS);
    REJECT(ENCBOUND_ERR_RANGE, encbound_sk_rand(a+60, 8));
    CHECK_EQ(encbound_sk_memset_s(b, 64, 0xa5, 64), 0);
    CHECK_EQ(encbound_sk_consttime_memequal(a, b, 64), 1);
    raw(b,64)[63] = 0;
    CHECK_EQ(encbound_sk_consttime_memequal(a, b, 64), 0);
    CHECK_EQ(encbound_sk_consttime_memequal(NULL, NULL, 0), 1);
    REJECT(ENCBOUND_ERR_RANGE, encbound_sk_consttime_memequal(a, b+60, 8));
    CHECK_EQ(encbound_sk_memset_s(b+60, 4, 7, 8), EOVERFLOW);
    CHECK(raw(b,64)[59] == 0xa5 && raw(b,64)[63] == 7);
    REJECT(ENCBOUND_ERR_RANGE, encbound_sk_memset_s(b+60, 8, 0, 8));
    CHECK_EQ(encbound_sk_memset_s(NULL, 4, 0, 4), EINVAL);
    CHECK_EQ(encbound_sk_memset_s(b, 0, 0, 0), 0);

    size_t sealed_size = encbound_sk_calc_sealed_data_size(0, 64);
    sgx_sealed_data_t *s = encbound_malloc(sealed_size);
    uint32_t *n = encbound_malloc(sizeof(*n)), *alen = encbound_malloc(sizeof(*alen));
    CHECK(s && n && alen);
    CHECK_EQ(encbound_sk_seal_data(0, a, 64, a, sealed_size, s), SGX_SUCCESS);
    CHECK_EQ(encbound_sk_get_encrypt_txt_len(s), 64);
    CHECK_EQ(encbound_sk_get_add_mac_txt_len(s), 0);
    CHECK_EQ(encbound_sk_get_encrypt_txt_len(NULL), UINT32_MAX);
    CHECK_EQ(encbound_sk_get_add_mac_txt_len(NULL), UINT32_MAX);
    REJECT(ENCBOUND_ERR_RANGE, encbound_sk_get_encrypt_txt_len((void *)small));
    REJECT(ENCBOUND_ERR_RANGE, encbound_sk_get_add_mac_txt_len((void *)small));
    void *stripped = (void *)(encbound_enclave_base() +
                              ((uintptr_t)s & ENCBOUND_OFFSET_MASK));
    REJECT(ENCBOUND_ERR_POLICY, encbound_sk_get_encrypt_txt_len(stripped));
    REJECT(ENCBOUND_ERR_POLICY, encbound_sk_rand(stripped, 8));
    REJECT(ENCBOUND_ERR_POLICY, encbound_sk_memset_s(stripped, 8, 0, 8));
    REJECT(ENCBOUND_ERR_POLICY, encbound_sk_consttime_memequal(stripped, a, 8));
#ifdef ENCBOUND_MAC27
    void *forged = (void *)((uintptr_t)s ^ (1ULL << ENCBOUND_TAG_SHIFT));
    REJECT(ENCBOUND_ERR_TAG, encbound_sk_get_encrypt_txt_len(forged));
#endif
    *(uint32_t *)raw(n,4) = 64;
    *(uint32_t *)raw(alen,4) = 123;
    CHECK_EQ(encbound_sk_unseal_data(s, a, alen, b, n), SGX_SUCCESS);
    CHECK_EQ(*(uint32_t *)raw(n,4), 64);
    CHECK_EQ(*(uint32_t *)raw(alen,4), 0);
    CHECK(memcmp(raw(a,64), raw(b,64), 64) == 0);

    sealed_size = encbound_sk_calc_sealed_data_size(4, 64);
    CHECK_EQ(encbound_sk_seal_data(4, a, 64, a, sealed_size, s), SGX_SUCCESS);
    *(uint32_t *)raw(n,4) = 64;
    *(uint32_t *)raw(alen,4) = 4;
    memset(raw(b,64), 0, 64);
    CHECK_EQ(encbound_sk_unseal_data(s, b, alen, plain, n), SGX_SUCCESS);
    CHECK(memcmp(raw(a,64), raw(b,64), 4) == 0);
    CHECK(memcmp(raw(a,64), raw(plain,64), 64) == 0);
    CHECK_EQ(*(uint32_t *)raw(alen,4), 4);
    CHECK_EQ(*(uint32_t *)raw(n,4), 64);
    encbound_free(a); encbound_free(b); encbound_free(plain);
    encbound_free(small); encbound_free(s); encbound_free(n); encbound_free(alen);
    return TEST_SUMMARY("sk_sgx_adapters_test");
}
