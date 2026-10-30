/* Checked SDK adapters for the ObliDB stateless crypto closure.
 * No context/SDK allocation escapes. Validate every full span before the call.
 * Empty input/AAD authorize no access, following the SDK's zero-length rule. */
#include <stddef.h>
#include <stdint.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#ifdef ENCBOUND_PROTECTED
#include "encbound_runtime.h"
static void *span(const void *p, size_t n, int access) {
    if (!n) return NULL;
    return (void *)encbound_require((uintptr_t)p,n,access);
}
#else
static void *span(const void *p, size_t n, int access) {
    (void)access;
    return n ? (void *)p : NULL;
}
#define ENCBOUND_ACCESS_READ 1
#define ENCBOUND_ACCESS_WRITE 2
#endif

sgx_status_t encbound_oblidb_rand(unsigned char *p, size_t n) {
    if (!p || !n) return SGX_ERROR_INVALID_PARAMETER;
    return sgx_read_rand(span(p,n,ENCBOUND_ACCESS_WRITE),n);
}

/* The application's block helpers always use nonempty messages and 12-byte IVs.
 * This selected adapter contract rejects other sizes before touching memory. */
static int valid(const void *key,const void *src,uint32_t n,void *dst,
                 const void *iv,uint32_t ivlen,const void *aad,uint32_t aadlen,const void *tag) {
    return key && src && n && dst && iv && ivlen==12 && (!aadlen || aad) && tag;
}

sgx_status_t encbound_oblidb_encrypt(const sgx_aes_gcm_128bit_key_t *key,
    const uint8_t *src, uint32_t n, uint8_t *dst, const uint8_t *iv,
    uint32_t ivlen, const uint8_t *aad, uint32_t aadlen, sgx_aes_gcm_128bit_tag_t *tag) {
    if (!valid(key,src,n,dst,iv,ivlen,aad,aadlen,tag)) return SGX_ERROR_INVALID_PARAMETER;
    const sgx_aes_gcm_128bit_key_t *k=span(key,sizeof(*key),ENCBOUND_ACCESS_READ);
    const uint8_t *s=span(src,n,ENCBOUND_ACCESS_READ);
    uint8_t *d=span(dst,n,ENCBOUND_ACCESS_WRITE);
    const uint8_t *v=span(iv,ivlen,ENCBOUND_ACCESS_READ);
    const uint8_t *a=span(aad,aadlen,ENCBOUND_ACCESS_READ);
    sgx_aes_gcm_128bit_tag_t *t=span(tag,sizeof(*tag),ENCBOUND_ACCESS_WRITE);
    return sgx_rijndael128GCM_encrypt(k,s,n,d,v,ivlen,a,aadlen,t);
}

sgx_status_t encbound_oblidb_decrypt(const sgx_aes_gcm_128bit_key_t *key,
    const uint8_t *src, uint32_t n, uint8_t *dst, const uint8_t *iv,
    uint32_t ivlen, const uint8_t *aad, uint32_t aadlen, const sgx_aes_gcm_128bit_tag_t *tag) {
    if (!valid(key,src,n,dst,iv,ivlen,aad,aadlen,tag)) return SGX_ERROR_INVALID_PARAMETER;
    const sgx_aes_gcm_128bit_key_t *k=span(key,sizeof(*key),ENCBOUND_ACCESS_READ);
    const uint8_t *s=span(src,n,ENCBOUND_ACCESS_READ);
    uint8_t *d=span(dst,n,ENCBOUND_ACCESS_WRITE);
    const uint8_t *v=span(iv,ivlen,ENCBOUND_ACCESS_READ);
    const uint8_t *a=span(aad,aadlen,ENCBOUND_ACCESS_READ);
    const sgx_aes_gcm_128bit_tag_t *t=span(tag,sizeof(*tag),ENCBOUND_ACCESS_READ);
    return sgx_rijndael128GCM_decrypt(k,s,n,d,v,ivlen,a,aadlen,t);
}
