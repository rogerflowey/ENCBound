/* Checked services for pinned YeeZ. Original ENCBound support, using the
 * validated RNG/GCM/CMAC/secure-memory patterns from apps/sgx-kms/adapters.c.
 * SDK algorithms are unchanged. This unit is TRUSTED, never instrumented. */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sgx_trts.h>
#include "encbound_runtime.h"
#ifdef ENCBOUND_PROTECTED
#define yeez_read_rand encbound_yeez_read_rand
#define yeez_encrypt encbound_yeez_encrypt
#define yeez_decrypt encbound_yeez_decrypt
#define yeez_cmac encbound_yeez_cmac
#define yeez_sha256 encbound_yeez_sha256
#define yeez_memset_s encbound_yeez_memset_s
#define yeez_dh_init encbound_yeez_dh_init
#define yeez_dh_msg1 encbound_yeez_dh_msg1
#define yeez_dh_msg3 encbound_yeez_dh_msg3
#endif
#include "adapters.h"
extern int memset_s(void *, size_t, int, size_t);

static void *span(const void *p, size_t n, int access)
{
    if (!n) return NULL;
#ifdef ENCBOUND_PROTECTED
    return (void *)encbound_require((uintptr_t)p, n, access);
#else
    (void)access; return (void *)p;
#endif
}
sgx_status_t yeez_read_rand(unsigned char *out, size_t n)
{
    if (!out || !n) return SGX_ERROR_INVALID_PARAMETER;
    return sgx_read_rand(span(out, n, ENCBOUND_ACCESS_WRITE), n);
}
sgx_status_t yeez_encrypt(const sgx_aes_gcm_128bit_key_t *key, const uint8_t *src, uint32_t n,
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
sgx_status_t yeez_decrypt(const sgx_aes_gcm_128bit_key_t *key, const uint8_t *src, uint32_t n,
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
sgx_status_t yeez_cmac(const sgx_cmac_128bit_key_t *key, const uint8_t *src, uint32_t n, sgx_cmac_128bit_tag_t *out)
{
    if (!key || !src || !out) return SGX_ERROR_INVALID_PARAMETER;
    uint8_t empty = 0;
    const void *k = span(key, 16, ENCBOUND_ACCESS_READ);
    const void *s = n ? span(src, n, ENCBOUND_ACCESS_READ) : &empty;
    void *d = span(out, 16, ENCBOUND_ACCESS_WRITE);
    return sgx_rijndael128_cmac_msg(k, s, n, d);
}
sgx_status_t yeez_sha256(const uint8_t *src, uint32_t n, sgx_sha256_hash_t *out)
{
    if (!src || !out) return SGX_ERROR_INVALID_PARAMETER;
    uint8_t empty = 0;
    const void *s = n ? span(src, n, ENCBOUND_ACCESS_READ) : &empty;
    void *d = span(out, sizeof(*out), ENCBOUND_ACCESS_WRITE);
    return sgx_sha256_msg(s, n, d);
}
int yeez_memset_s(void *p, size_t capacity, int c, size_t count)
{
    uint8_t empty;
    size_t n = count < capacity ? count : capacity;
    void *d = !p ? NULL : n ? span(p, n, ENCBOUND_ACCESS_WRITE) : &empty;
    return memset_s(d, capacity, c, count);
}

/* Pinned sgx_internal_dh_session_t contains only values, no pointers/handles.
 * Its 200-byte caller-owned state remains application data. Private staging
 * satisfies the SDK's enclave-residency rule without returning SDK addresses.
 * YeeZ uses distinct message/session/key/identity objects; overlapping extents
 * reject explicitly rather than changing alias behavior through staging. */
_Static_assert(sizeof(sgx_dh_session_t) == 200, "pinned DH session size");
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    if (!a || !b || !an || !bn) return 0;
    uintptr_t x=(uintptr_t)a, y=(uintptr_t)b;
    return x<=y ? y-x<an : x-y<bn;
}
sgx_status_t yeez_dh_init(sgx_dh_session_role_t role, sgx_dh_session_t *session)
{
    if (!session) return SGX_ERROR_INVALID_PARAMETER;
    void *s=span(session, sizeof(*session), ENCBOUND_ACCESS_READWRITE);
    sgx_dh_session_t local;
    memcpy(&local,s,sizeof local);
    sgx_status_t status=sgx_dh_init_session(role,&local);
    memcpy(s,&local,sizeof local);
    memset_s(&local,sizeof local,0,sizeof local);
    return status;
}
sgx_status_t yeez_dh_msg1(const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_dh_session_t *session)
{
    if (!session) return SGX_ERROR_INVALID_PARAMETER;
    void *s=span(session,sizeof(*session),ENCBOUND_ACCESS_READWRITE);
    const void *a=msg1 ? span(msg1,sizeof(*msg1),ENCBOUND_ACCESS_READ) : NULL;
    void *b=msg2 ? span(msg2,sizeof(*msg2),ENCBOUND_ACCESS_READWRITE) : NULL;
    if (overlap(s,sizeof(*session),a,sizeof(*msg1)) || overlap(s,sizeof(*session),b,sizeof(*msg2)) ||
        overlap(a,sizeof(*msg1),b,sizeof(*msg2))) return SGX_ERROR_INVALID_PARAMETER;
    sgx_dh_session_t ls; sgx_dh_msg1_t la; sgx_dh_msg2_t lb;
    memcpy(&ls,s,sizeof ls);
    if(a) memcpy(&la,a,sizeof la);
    if(b) memcpy(&lb,b,sizeof lb);
    sgx_status_t status=sgx_LAv1_initiator_proc_msg1(a ? &la : NULL,b ? &lb : NULL,&ls);
    memcpy(s,&ls,sizeof ls);
    if(b) memcpy(b,&lb,sizeof lb);
    memset_s(&ls,sizeof ls,0,sizeof ls);
    return status;
}
sgx_status_t yeez_dh_msg3(const sgx_dh_msg3_t *msg3, sgx_dh_session_t *session,
    sgx_key_128bit_t *key, sgx_dh_session_enclave_identity_t *identity)
{
    if (!session) return SGX_ERROR_INVALID_PARAMETER;
    void *s=span(session,sizeof(*session),ENCBOUND_ACCESS_READWRITE);
    void *k=key ? span(key,sizeof(*key),ENCBOUND_ACCESS_READWRITE) : NULL;
    void *i=identity ? span(identity,sizeof(*identity),ENCBOUND_ACCESS_READWRITE) : NULL;
    const void *m=NULL;
    size_t total=0;
    sgx_dh_msg3_t header={0};
    if(msg3) {
        memcpy(&header,span(msg3,sizeof header,ENCBOUND_ACCESS_READ),sizeof header);
        if(header.msg3_body.additional_prop_length > UINT_MAX-sizeof header) return SGX_ERROR_INVALID_PARAMETER;
        total=sizeof header+header.msg3_body.additional_prop_length;
        m=span(msg3,total,ENCBOUND_ACCESS_READ);
    }
    if(overlap(s,sizeof(*session),k,sizeof(*key)) || overlap(s,sizeof(*session),i,sizeof(*identity)) ||
       overlap(k,sizeof(*key),i,sizeof(*identity)) || overlap(m,total,s,sizeof(*session)) ||
       overlap(m,total,k,sizeof(*key)) || overlap(m,total,i,sizeof(*identity))) return SGX_ERROR_INVALID_PARAMETER;
    sgx_dh_msg3_t *lm=NULL;
    if(m) {
        lm=malloc(total);
        if(!lm) return SGX_ERROR_OUT_OF_MEMORY;
        memcpy(lm,m,total);
        /* Host memory can change between copies. SDK sees only the validated
         * snapshot length, even if a second read contained a larger value. */
        lm->msg3_body.additional_prop_length=header.msg3_body.additional_prop_length;
    }
    sgx_dh_session_t ls; sgx_key_128bit_t lk={0}; sgx_dh_session_enclave_identity_t li;
    memcpy(&ls,s,sizeof ls);
    if(k) memcpy(&lk,k,sizeof lk);
    if(i) memcpy(&li,i,sizeof li);
    sgx_status_t status=sgx_LAv1_initiator_proc_msg3(lm,&ls,k ? &lk : NULL,i ? &li : NULL);
    memcpy(s,&ls,sizeof ls);
    if(k) memcpy(k,&lk,sizeof lk);
    if(i) memcpy(i,&li,sizeof li);
    memset_s(&ls,sizeof ls,0,sizeof ls);
    memset_s(&lk,sizeof lk,0,sizeof lk);
    if(lm) { memset_s(lm,total,0,total); free(lm); }
    return status;
}
