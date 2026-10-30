/* Native checked-service contracts over the real runtime/fake platform.
 * SDK functions are recording spies; this file supplies no crypto/SGX result. */
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
int memset_s(void *, size_t, int, size_t);
int consttime_memequal(const void *, const void *, size_t);
#include "adapters.c"
#include "encbound_platform.h"
#include "fake_platform.h"

static unsigned services, rejections;
static sgx_status_t service_status;
static const void *expected_key;
static size_t expected_size;
#define DENIED(expr, code) do { \
    unsigned before = services; fake_abort_active = 1; \
    if (setjmp(fake_abort_env) == 0) { (void)(expr); assert(!"missing range rejection"); } \
    else { assert(fake_abort_code == (code)); assert(services == before); ++rejections; } \
    fake_abort_active = 0; \
} while (0)
static void raw(const void *p, size_t n, int access)
{
    uintptr_t decoded = 0;
    assert(p && encbound_check((uintptr_t)p, n, access, &decoded) == ENCBOUND_ERR_POLICY);
}
sgx_status_t sgx_ra_init(const sgx_ec256_public_t *key, int pse, sgx_ra_context_t *context)
{
    ++services; assert(!pse && key && context && key != expected_key);
    assert(!memcmp(key, expected_key, sizeof(*key)));
    *context = 73; return service_status;
}
sgx_status_t sgx_ra_get_keys(sgx_ra_context_t context, sgx_ra_key_type_t type, sgx_ra_key_128_t *key)
{
    ++services; assert(context == 73 && type == SGX_RA_KEY_SK);
    memset(key, 0x7c, sizeof(*key)); return service_status;
}
sgx_status_t sgx_ra_close(sgx_ra_context_t context) { ++services; assert(context == 73); return service_status; }
sgx_status_t sgx_create_report(const sgx_target_info_t *target, const sgx_report_data_t *data, sgx_report_t *report)
{
    ++services; assert(target && data && report && report != expected_key);
    assert(((const uint8_t *)target)[0] == 0x55 && data->d[0] == 0x66);
    memset(report, 0x8e, sizeof(*report)); return service_status;
}
sgx_status_t sgx_read_rand(unsigned char *p, size_t n) { ++services; raw(p,n,ENCBOUND_ACCESS_WRITE); memset(p, 0x19, n); return service_status; }
sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *key, const uint8_t *src, uint32_t n,
    uint8_t *dst, const uint8_t *iv, uint32_t ivn, const uint8_t *aad, uint32_t an, sgx_aes_gcm_128bit_tag_t *tag)
{
    ++services; raw(key,16,ENCBOUND_ACCESS_READ); raw(iv,ivn,ENCBOUND_ACCESS_READ); raw(tag,16,ENCBOUND_ACCESS_WRITE);
    assert(ivn == 12 && (src || aad));
    if (n) { raw(src,n,ENCBOUND_ACCESS_READ); raw(dst,n,ENCBOUND_ACCESS_WRITE); memcpy(dst,src,n); }
    if (an) raw(aad,an,ENCBOUND_ACCESS_READ);
    return service_status;
}
sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *key, const uint8_t *src, uint32_t n,
    uint8_t *dst, const uint8_t *iv, uint32_t ivn, const uint8_t *aad, uint32_t an, const sgx_aes_gcm_128bit_tag_t *tag)
{ return sgx_rijndael128GCM_encrypt(key,src,n,dst,iv,ivn,aad,an,(sgx_aes_gcm_128bit_tag_t *)tag); }
sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *key, const uint8_t *src, uint32_t n, sgx_cmac_128bit_tag_t *tag)
{
    ++services; raw(key,16,ENCBOUND_ACCESS_READ); raw(tag,16,ENCBOUND_ACCESS_WRITE); assert(src);
    if (n) raw(src,n,ENCBOUND_ACCESS_READ);
    return service_status;
}
uint32_t sgx_calc_sealed_data_size(uint32_t an, uint32_t n)
{
    uint64_t total = (uint64_t)an+n+sizeof(sgx_sealed_data_t);
    return total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
}
uint32_t sgx_get_encrypt_txt_len(const sgx_sealed_data_t *p) { return p->plain_text_offset; }
uint32_t sgx_get_add_mac_txt_len(const sgx_sealed_data_t *p) { return p->aes_data.payload_size-p->plain_text_offset; }
sgx_status_t sgx_seal_data(uint32_t an, const uint8_t *aad, uint32_t n, const uint8_t *text, uint32_t size, sgx_sealed_data_t *out)
{
    ++services; assert(size == expected_size); raw(out,size,ENCBOUND_ACCESS_WRITE);
    if (an) raw(aad,an,ENCBOUND_ACCESS_READ);
    if (n) raw(text,n,ENCBOUND_ACCESS_READ);
    return service_status;
}
sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *p, uint8_t *aad, uint32_t *an, uint8_t *text, uint32_t *n)
{
    ++services; uint32_t len = sgx_get_encrypt_txt_len(p), alen = sgx_get_add_mac_txt_len(p);
    raw(p,sgx_calc_sealed_data_size(alen,len),ENCBOUND_ACCESS_READ);
    raw(n,4,ENCBOUND_ACCESS_READWRITE); raw(text,len,ENCBOUND_ACCESS_WRITE);
    if (an) raw(an,4,ENCBOUND_ACCESS_READWRITE);
    if (alen) raw(aad,alen,ENCBOUND_ACCESS_WRITE);
    *n = len; if (an) *an = alen;
    memset(text, 0x24, len); return service_status;
}
int memset_s(void *p, size_t capacity, int c, size_t n)
{
    if (!p) return EINVAL;
    memset(p,c,n < capacity ? n : capacity); return n > capacity ? EOVERFLOW : 0;
}
int consttime_memequal(const void *a, const void *b, size_t n) { return !memcmp(a,b,n); }
static void *allocate(size_t n, void **decoded)
{
    void *p = encbound_malloc(n); assert(p);
    *decoded = (void *)encbound_require((uintptr_t)p,n,ENCBOUND_ACCESS_READWRITE);
    memset(*decoded,0,n); return p;
}
int main(void)
{
    assert(encbound_runtime_init_with_key(0x0706050403020100ull,0x0f0e0d0c0b0a0908ull) == ENCBOUND_OK);
    void *kr, *br, *dr, *vr, *tr, *cr, *rr, *tir, *rdr, *sr, *nr, *ar;
    sgx_ec256_public_t *key = allocate(64,&kr);
    uint8_t *bytes = allocate(32,&br), *dst = allocate(32,&dr), *iv = allocate(16,&vr), *tag = allocate(16,&tr);
    sgx_ra_context_t *context = allocate(4,&cr);
    sgx_report_t *report = allocate(512,&rr);
    sgx_target_info_t *target = allocate(sizeof(*target),&tir);
    sgx_report_data_t *data = allocate(sizeof(*data),&rdr);
    uint32_t size = sgx_calc_sealed_data_size(0,16);
    sgx_sealed_data_t *sealed = allocate(1024,&sr);
    uint32_t *n = allocate(4,&nr), *an = allocate(4,&ar);
    expected_key = kr;
    assert(encbound_kms_ra_init(key,1,context) == SGX_ERROR_FEATURE_NOT_SUPPORTED && !services);
    DENIED(encbound_kms_ra_init(key,0,(void *)((uintptr_t)context+14)),ENCBOUND_ERR_RANGE);
    DENIED(encbound_kms_ra_init((void *)((uintptr_t)key+32),0,context),ENCBOUND_ERR_RANGE);
    service_status = SGX_ERROR_UNEXPECTED; *(uint32_t *)cr = 9;
    assert(encbound_kms_ra_init(key,0,context) == service_status && *(uint32_t *)cr == 9);
    service_status = SGX_SUCCESS;
    assert(encbound_kms_ra_init(key,0,context) == SGX_SUCCESS && *(uint32_t *)cr == 73);
    DENIED(encbound_kms_ra_get_keys(73,SGX_RA_KEY_SK,(void *)((uintptr_t)tag+8)),ENCBOUND_ERR_RANGE);
    service_status = SGX_ERROR_INVALID_STATE; memset(tr,0x11,16);
    assert(encbound_kms_ra_get_keys(73,SGX_RA_KEY_SK,(void *)tag) == service_status && ((uint8_t *)tr)[0] == 0x11);
    service_status = SGX_SUCCESS;
    assert(encbound_kms_ra_get_keys(73,SGX_RA_KEY_SK,(void *)tag) == SGX_SUCCESS && ((uint8_t *)tr)[0] == 0x7c);
    assert(encbound_kms_ra_close(73) == SGX_SUCCESS);
    ((uint8_t *)tir)[0] = 0x55; ((uint8_t *)rdr)[0] = 0x66; expected_key = rr;
    DENIED(encbound_kms_create_report(target,data,(void *)((uintptr_t)report+256)),ENCBOUND_ERR_RANGE);
    service_status = SGX_ERROR_UNEXPECTED;
    assert(encbound_kms_create_report(target,data,report) == service_status && ((uint8_t *)rr)[0] == 0);
    service_status = SGX_SUCCESS;
    assert(encbound_kms_create_report(target,data,report) == SGX_SUCCESS && ((uint8_t *)rr)[0] == 0x8e);
    DENIED(encbound_kms_read_rand(tag,17),ENCBOUND_ERR_RANGE);
    assert(encbound_kms_read_rand(tag,16) == SGX_SUCCESS);
#define ENCRYPT(k,s,z,d,v,vn,a,az,t) encbound_kms_encrypt((void *)(k),s,z,d,v,vn,a,az,(void *)(t))
    DENIED(ENCRYPT((void *)((uintptr_t)tag+1),bytes,16,dst,iv,12,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENIED(ENCRYPT(tag,bytes,33,dst,iv,12,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENIED(ENCRYPT(tag,bytes,16,(void *)((uintptr_t)dst+24),iv,12,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENIED(ENCRYPT(tag,bytes,16,dst,(void *)((uintptr_t)iv+8),12,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENIED(ENCRYPT(tag,bytes,16,dst,iv,12,bytes,33,tag),ENCBOUND_ERR_RANGE);
    DENIED(ENCRYPT(tag,bytes,16,dst,iv,12,NULL,0,(void *)((uintptr_t)tag+1)),ENCBOUND_ERR_RANGE);
    assert(ENCRYPT(tag,bytes,16,dst,iv,12,NULL,0,tag) == SGX_SUCCESS);
    assert(ENCRYPT(tag,bytes,0,dst,iv,12,NULL,0,tag) == SGX_SUCCESS);
    DENIED(encbound_kms_decrypt((void *)tag,bytes,16,dst,iv,12,NULL,0,(void *)((uintptr_t)tag+1)),ENCBOUND_ERR_RANGE);
    assert(encbound_kms_decrypt((void *)tag,bytes,16,dst,iv,12,NULL,0,(void *)tag) == SGX_SUCCESS);
    DENIED(encbound_kms_cmac((void *)tag,bytes,33,(void *)tag),ENCBOUND_ERR_RANGE);
    assert(encbound_kms_cmac((void *)tag,bytes,0,(void *)tag) == SGX_SUCCESS);
    assert(encbound_kms_cmac((void *)tag,NULL,0,(void *)tag) == SGX_ERROR_INVALID_PARAMETER);
    expected_size = size;
    DENIED(encbound_kms_seal(0,NULL,33,bytes,size,sealed),ENCBOUND_ERR_RANGE);
    DENIED(encbound_kms_seal(0,NULL,16,bytes,1025,sealed),ENCBOUND_ERR_RANGE);
    assert(encbound_kms_seal(0,NULL,16,bytes,size,sealed) == SGX_SUCCESS);
    ((sgx_sealed_data_t *)sr)->plain_text_offset = 16;
    ((sgx_sealed_data_t *)sr)->aes_data.payload_size = 16;
    assert(encbound_kms_text_len(sealed) == 16 && encbound_kms_aad_len(sealed) == 0);
    DENIED(encbound_kms_text_len((void *)((uintptr_t)sealed+1000)),ENCBOUND_ERR_RANGE);
    *(uint32_t *)nr = 32; *(uint32_t *)ar = 0;
    DENIED(encbound_kms_unseal(sealed,NULL,an,(void *)((uintptr_t)dst+24),n),ENCBOUND_ERR_RANGE);
    DENIED(encbound_kms_unseal(sealed,NULL,an,dst,(void *)((uintptr_t)n+14)),ENCBOUND_ERR_RANGE);
    ((sgx_sealed_data_t *)sr)->aes_data.payload_size = 2048;
    DENIED(encbound_kms_unseal(sealed,bytes,an,dst,n),ENCBOUND_ERR_RANGE);
    ((sgx_sealed_data_t *)sr)->aes_data.payload_size = 16;
    assert(encbound_kms_unseal(sealed,NULL,an,dst,n) == SGX_SUCCESS && *(uint32_t *)nr == 16 && *(uint32_t *)ar == 0);
    DENIED(encbound_kms_memset_s(tag,17,0,17),ENCBOUND_ERR_RANGE);
    assert(encbound_kms_memset_s(tag,16,0,32) == EOVERFLOW);
    DENIED(encbound_kms_memequal(bytes,(void *)((uintptr_t)bytes+24),16),ENCBOUND_ERR_RANGE);
    assert(encbound_kms_memequal(bytes,bytes,16));
    void *private = (void *)(encbound_enclave_base()+0x300000);
    DENIED(encbound_kms_read_rand(private,16),ENCBOUND_ERR_POLICY);
    assert(rejections == 22);
    printf("SGX-KMS ADAPTER NATIVE PASS rejections=%u service_calls=%u\n",rejections,services);
    return 0;
}
