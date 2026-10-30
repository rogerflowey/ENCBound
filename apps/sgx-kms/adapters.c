/* Exact checked SDK services for the pinned SGX-KMS application. Original
 * ENCBound support; SDK state and staging remain in the trusted domain. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_trts.h>
#include <sgx_utils.h>
#include "encbound_runtime.h"
#ifndef ENCBOUND_PROTECTED
#define encbound_kms_ra_init kms_ra_init
#define encbound_kms_ra_get_keys kms_ra_get_keys
#define encbound_kms_ra_close kms_ra_close
#define encbound_kms_create_report kms_create_report
#define encbound_kms_read_rand kms_read_rand
#define encbound_kms_encrypt kms_encrypt
#define encbound_kms_decrypt kms_decrypt
#define encbound_kms_cmac kms_cmac
#define encbound_kms_seal kms_seal
#define encbound_kms_unseal kms_unseal
#define encbound_kms_sealed_size kms_sealed_size
#define encbound_kms_text_len kms_text_len
#define encbound_kms_aad_len kms_aad_len
#define encbound_kms_memset_s kms_memset_s
#define encbound_kms_memequal kms_memequal
#endif
static void *span(const void *p, size_t n, int access)
{
    if (!n) return NULL;
#ifdef ENCBOUND_PROTECTED
    return (void *)encbound_require((uintptr_t)p, n, access);
#else
    (void)access; return (void *)p;
#endif
}
sgx_status_t encbound_kms_ra_init(const sgx_ec256_public_t *key, int pse, sgx_ra_context_t *out)
{
    if (pse) return SGX_ERROR_FEATURE_NOT_SUPPORTED;
    if (!key || !out) return SGX_ERROR_INVALID_PARAMETER;
    const void *in = span(key, sizeof(*key), ENCBOUND_ACCESS_READ);
    void *dst = span(out, sizeof(*out), ENCBOUND_ACCESS_WRITE);
    sgx_ec256_public_t local; sgx_ra_context_t context = 0;
    memcpy(&local, in, sizeof local);
    sgx_status_t status = sgx_ra_init(&local, 0, &context);
    if (status == SGX_SUCCESS) memcpy(dst, &context, sizeof context);
    return status;
}
sgx_status_t encbound_kms_ra_get_keys(sgx_ra_context_t context, sgx_ra_key_type_t type, sgx_ra_key_128_t *out)
{
    if (!out) return SGX_ERROR_INVALID_PARAMETER;
    void *dst = span(out, sizeof(*out), ENCBOUND_ACCESS_WRITE);
    sgx_ra_key_128_t key = {0};
    sgx_status_t status = sgx_ra_get_keys(context, type, &key);
    if (status == SGX_SUCCESS) memcpy(dst, key, sizeof key);
    memset_s(key, sizeof key, 0, sizeof key);
    return status;
}
sgx_status_t encbound_kms_ra_close(sgx_ra_context_t context) { return sgx_ra_close(context); }
sgx_status_t encbound_kms_create_report(const sgx_target_info_t *target, const sgx_report_data_t *data, sgx_report_t *report)
{
    if (!report) return SGX_ERROR_INVALID_PARAMETER;
    const void *t = target ? span(target, sizeof(*target), ENCBOUND_ACCESS_READ) : NULL;
    const void *d = data ? span(data, sizeof(*data), ENCBOUND_ACCESS_READ) : NULL;
    void *out = span(report, sizeof(*report), ENCBOUND_ACCESS_WRITE);
    sgx_target_info_t lt; sgx_report_data_t ld; sgx_report_t lr = {0};
    if (t) memcpy(&lt, t, sizeof lt);
    if (d) memcpy(&ld, d, sizeof ld);
    sgx_status_t status = sgx_create_report(t ? &lt : NULL, d ? &ld : NULL, &lr);
    if (status == SGX_SUCCESS) memcpy(out, &lr, sizeof lr);
    return status;
}
sgx_status_t encbound_kms_read_rand(unsigned char *out, size_t n)
{
    if (!out || !n) return SGX_ERROR_INVALID_PARAMETER;
    return sgx_read_rand(span(out, n, ENCBOUND_ACCESS_WRITE), n);
}
/* Preserve optional zero-length pointer presence with private dummy storage.
 * SDK GCM rejects src == aad == NULL even for an empty message; no application
 * pointee access is authorized by a zero length. */
sgx_status_t encbound_kms_encrypt(const sgx_aes_gcm_128bit_key_t *key, const uint8_t *src, uint32_t n,
    uint8_t *dst, const uint8_t *iv, uint32_t ivn, const uint8_t *aad, uint32_t an, sgx_aes_gcm_128bit_tag_t *tag)
{
    if (!key || (n && (!src || !dst)) || !iv || ivn != 12 || (an && !aad) || !tag) return SGX_ERROR_INVALID_PARAMETER;
    uint8_t empty = 0;
    const void *k = span(key, 16, ENCBOUND_ACCESS_READ);
    const void *s = n ? span(src, n, ENCBOUND_ACCESS_READ) : src ? &empty : NULL;
    void *d = n ? span(dst, n, ENCBOUND_ACCESS_WRITE) : dst ? &empty : NULL;
    const void *v = span(iv, ivn, ENCBOUND_ACCESS_READ);
    const void *a = an ? span(aad, an, ENCBOUND_ACCESS_READ) : aad ? &empty : NULL;
    void *t = span(tag, 16, ENCBOUND_ACCESS_WRITE);
    return sgx_rijndael128GCM_encrypt(k, s, n, d, v, ivn, a, an, t);
}
sgx_status_t encbound_kms_decrypt(const sgx_aes_gcm_128bit_key_t *key, const uint8_t *src, uint32_t n,
    uint8_t *dst, const uint8_t *iv, uint32_t ivn, const uint8_t *aad, uint32_t an, const sgx_aes_gcm_128bit_tag_t *tag)
{
    if (!key || (n && (!src || !dst)) || !iv || ivn != 12 || (an && !aad) || !tag) return SGX_ERROR_INVALID_PARAMETER;
    uint8_t empty = 0;
    const void *k = span(key, 16, ENCBOUND_ACCESS_READ);
    const void *s = n ? span(src, n, ENCBOUND_ACCESS_READ) : src ? &empty : NULL;
    void *d = n ? span(dst, n, ENCBOUND_ACCESS_WRITE) : dst ? &empty : NULL;
    const void *v = span(iv, ivn, ENCBOUND_ACCESS_READ);
    const void *a = an ? span(aad, an, ENCBOUND_ACCESS_READ) : aad ? &empty : NULL;
    const void *t = span(tag, 16, ENCBOUND_ACCESS_READ);
    return sgx_rijndael128GCM_decrypt(k, s, n, d, v, ivn, a, an, t);
}
sgx_status_t encbound_kms_cmac(const sgx_cmac_128bit_key_t *key, const uint8_t *src, uint32_t n, sgx_cmac_128bit_tag_t *out)
{
    if (!key || !src || !out) return SGX_ERROR_INVALID_PARAMETER;
    uint8_t empty = 0;
    const void *k = span(key, sizeof(*key), ENCBOUND_ACCESS_READ);
    const void *s = n ? span(src, n, ENCBOUND_ACCESS_READ) : &empty;
    void *d = span(out, sizeof(*out), ENCBOUND_ACCESS_WRITE);
    return sgx_rijndael128_cmac_msg(k, s, n, d);
}
uint32_t encbound_kms_sealed_size(uint32_t aad, uint32_t text) { return sgx_calc_sealed_data_size(aad, text); }
uint32_t encbound_kms_text_len(const sgx_sealed_data_t *p)
{
    if (!p) return UINT32_MAX;
    return sgx_get_encrypt_txt_len(span(p, sizeof(*p), ENCBOUND_ACCESS_READ));
}
uint32_t encbound_kms_aad_len(const sgx_sealed_data_t *p)
{
    if (!p) return UINT32_MAX;
    return sgx_get_add_mac_txt_len(span(p, sizeof(*p), ENCBOUND_ACCESS_READ));
}
sgx_status_t encbound_kms_seal(uint32_t an, const uint8_t *aad, uint32_t n, const uint8_t *text, uint32_t size, sgx_sealed_data_t *out)
{
    if ((an && !aad) || (n && !text) || !out) return SGX_ERROR_INVALID_PARAMETER;
    const void *a = span(aad, an, ENCBOUND_ACCESS_READ);
    const void *s = span(text, n, ENCBOUND_ACCESS_READ);
    void *d = span(out, size, ENCBOUND_ACCESS_WRITE);
    return sgx_seal_data(an, a, n, s, size, d);
}
sgx_status_t encbound_kms_unseal(const sgx_sealed_data_t *input, uint8_t *aad, uint32_t *an, uint8_t *text, uint32_t *n)
{
    if (!input || !n || !text) return SGX_ERROR_INVALID_PARAMETER;
    const sgx_sealed_data_t *header = span(input, sizeof(*input), ENCBOUND_ACCESS_READ);
    uint32_t alen = sgx_get_add_mac_txt_len(header), len = sgx_get_encrypt_txt_len(header);
    uint32_t total = sgx_calc_sealed_data_size(alen, len);
    if (total == UINT32_MAX) return SGX_ERROR_MAC_MISMATCH;
    const void *s = span(input, total, ENCBOUND_ACCESS_READ);
    uint32_t *capacity = span(n, sizeof(*n), ENCBOUND_ACCESS_READWRITE);
    uint32_t *acap = an ? span(an, sizeof(*an), ENCBOUND_ACCESS_READWRITE) : NULL;
    if (*capacity < len || (alen && (!aad || !acap || *acap < alen))) return SGX_ERROR_INVALID_PARAMETER;
    void *d = span(text, len, ENCBOUND_ACCESS_WRITE);
    void *a = span(aad, alen, ENCBOUND_ACCESS_WRITE);
    /* The upstream supplies a nonnull zero AAD-length cell. Preserve SDK semantics. */
    return sgx_unseal_data(s, a, acap, d, capacity);
}
int encbound_kms_memset_s(void *p, size_t capacity, int c, size_t count)
{
    unsigned char empty; size_t n = count < capacity ? count : capacity;
    void *dst = !p ? NULL : n ? span(p, n, ENCBOUND_ACCESS_WRITE) : &empty;
    return memset_s(dst, capacity, c, count);
}
int encbound_kms_memequal(const void *a, const void *b, size_t n)
{
    return consttime_memequal(span(a, n, ENCBOUND_ACCESS_READ), span(b, n, ENCBOUND_ACCESS_READ), n);
}
