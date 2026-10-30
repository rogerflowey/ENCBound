/* Real checker/allocator with recording SDK spies: native contract evidence. */
#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_dh.h>
static void *test_alloc(size_t);
#define malloc test_alloc
#include "adapters.c"
#undef malloc
#include "fake_platform.h"
#include "encbound_platform.h"

static unsigned calls, denied;
static sgx_status_t service_status;
static int allocation_failure;
static sgx_dh_msg3_t *racing_header;
static uint32_t expected_tail;
static void *session_raw, *msg1_raw, *msg2_raw, *key_raw, *identity_raw;
static void *test_alloc(size_t n)
{
    if(allocation_failure) return NULL;
    if(racing_header) racing_header->msg3_body.additional_prop_length=UINT32_MAX;
    return malloc(n);
}
#define DENY(expr,code) do { unsigned before=calls; fake_abort_active=1; \
 if(setjmp(fake_abort_env)==0) { (void)(expr); assert(!"missing rejection"); } \
 else { assert(fake_abort_code==(code)); assert(calls==before); ++denied; } \
 fake_abort_active=0; } while(0)
static void decoded(const void *p,size_t n,int access)
{
    uintptr_t out=0;
    assert(encbound_check((uintptr_t)p,n,access,&out)==ENCBOUND_ERR_POLICY);
}
int memset_s(void *p,size_t capacity,int c,size_t n)
{
    if(!p)return EINVAL;
    memset(p,c,n<capacity?n:capacity);
    return n>capacity?EOVERFLOW:0;
}
sgx_status_t sgx_read_rand(unsigned char *p,size_t n)
{ ++calls;decoded(p,n,ENCBOUND_ACCESS_WRITE);memset(p,0x19,n);return service_status; }
sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *k,const uint8_t *s,uint32_t n,
    uint8_t *d,const uint8_t *iv,uint32_t ivn,const uint8_t *a,uint32_t an,sgx_aes_gcm_128bit_tag_t *t)
{
    ++calls;decoded(k,16,ENCBOUND_ACCESS_READ);decoded(iv,ivn,ENCBOUND_ACCESS_READ);
    decoded(t,16,ENCBOUND_ACCESS_WRITE);assert(ivn==12);
    if(n){decoded(s,n,ENCBOUND_ACCESS_READ);decoded(d,n,ENCBOUND_ACCESS_WRITE);memcpy(d,s,n);}
    if(an)decoded(a,an,ENCBOUND_ACCESS_READ);
    return service_status;
}
sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *k,const uint8_t *s,uint32_t n,
    uint8_t *d,const uint8_t *iv,uint32_t ivn,const uint8_t *a,uint32_t an,const sgx_aes_gcm_128bit_tag_t *t)
{ return sgx_rijndael128GCM_encrypt(k,s,n,d,iv,ivn,a,an,(sgx_aes_gcm_128bit_tag_t *)t); }
sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *k,const uint8_t *s,uint32_t n,sgx_cmac_128bit_tag_t *t)
{
    ++calls;decoded(k,16,ENCBOUND_ACCESS_READ);decoded(t,16,ENCBOUND_ACCESS_WRITE);
    assert(s);if(n)decoded(s,n,ENCBOUND_ACCESS_READ);memset(t,0x51,16);return service_status;
}
sgx_status_t sgx_sha256_msg(const uint8_t *s,uint32_t n,sgx_sha256_hash_t *out)
{ ++calls;assert(s);if(n)decoded(s,n,ENCBOUND_ACCESS_READ);decoded(out,32,ENCBOUND_ACCESS_WRITE);memset(out,0x52,32);return service_status; }
sgx_status_t sgx_dh_init_session(sgx_dh_session_role_t role,sgx_dh_session_t *s)
{ ++calls;assert(s!=(void *)session_raw);assert(s->sgx_dh_session[0]==0x20);s->sgx_dh_session[0]=(uint8_t)role;return service_status; }
sgx_status_t sgx_LAv1_initiator_proc_msg1(const sgx_dh_msg1_t *a,sgx_dh_msg2_t *b,sgx_dh_session_t *s)
{
    ++calls;assert(s!=session_raw && s->sgx_dh_session[0]==0x20);
    assert(a!=msg1_raw && b!=msg2_raw);
    if(a)assert(a->g_a.gx[0]==0x31);
    if(b)b->g_b.gx[0]=0x32;
    s->sgx_dh_session[0]=0x21;return service_status;
}
sgx_status_t sgx_LAv1_initiator_proc_msg3(const sgx_dh_msg3_t *m,sgx_dh_session_t *s,
    sgx_key_128bit_t *key,sgx_dh_session_enclave_identity_t *id)
{
    ++calls;assert(s!=session_raw && key!=key_raw && id!=identity_raw);
    assert(s->sgx_dh_session[0]==0x20);
    if(m){assert(m->msg3_body.additional_prop_length==expected_tail);
        if(expected_tail)assert(m->msg3_body.additional_prop[expected_tail-1]==0x73);}
    if(key)memset(key,0x41,16);
    if(id)id->isv_prod_id=0x42;
    s->sgx_dh_session[0]=0x22;return service_status;
}
static void *allocate(size_t n,void **raw)
{
    void *p=encbound_malloc(n);assert(p);
    *raw=(void *)encbound_require((uintptr_t)p,n,ENCBOUND_ACCESS_READWRITE);
    memset(*raw,0,n);return p;
}
static void state(void){memset(session_raw,0x20,sizeof(sgx_dh_session_t));}
int main(void)
{
    assert(encbound_runtime_init_with_key(1,2)==ENCBOUND_OK);
    void *kr,*sr,*dr,*vr,*tr,*hr,*mr;
    uint8_t *key=allocate(16,&kr),*src=allocate(32,&sr),*dst=allocate(32,&dr);
    uint8_t *iv=allocate(16,&vr),*tag=allocate(16,&tr),*hash=allocate(32,&hr);
    sgx_dh_session_t *session=allocate(256,&session_raw);
    sgx_dh_msg1_t *m1=allocate(1024,&msg1_raw);
    sgx_dh_msg2_t *m2=allocate(512,&msg2_raw);
    sgx_dh_msg3_t *m3=allocate(1024,&mr);
    sgx_key_128bit_t *aek=allocate(16,&key_raw);
    sgx_dh_session_enclave_identity_t *identity=allocate(512,&identity_raw);
    service_status=SGX_SUCCESS;
    DENY(yeez_read_rand(key,17),ENCBOUND_ERR_RANGE);
    assert(yeez_read_rand(key,16)==SGX_SUCCESS && ((uint8_t *)kr)[0]==0x19);
    assert(yeez_read_rand(NULL,1)==SGX_ERROR_INVALID_PARAMETER);
#define GCM(k,s,n,d,v,a,an,t) yeez_encrypt((void *)(k),s,n,d,v,12,a,an,(void *)(t))
    DENY(GCM(key+1,src,16,dst,iv,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENY(GCM(key,src,33,dst,iv,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENY(GCM(key,src,16,dst+24,iv,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENY(GCM(key,src,16,dst,iv+8,NULL,0,tag),ENCBOUND_ERR_RANGE);
    DENY(GCM(key,src,16,dst,iv,src,33,tag),ENCBOUND_ERR_RANGE);
    DENY(GCM(key,src,16,dst,iv,NULL,0,tag+1),ENCBOUND_ERR_RANGE);
    assert(GCM(key,src,16,dst,iv,NULL,0,tag)==SGX_SUCCESS);
    assert(GCM(key,src,0,dst,iv,NULL,0,tag)==SGX_SUCCESS);
    DENY(yeez_decrypt((void *)key,src,16,dst,iv,12,NULL,0,(void *)(tag+1)),ENCBOUND_ERR_RANGE);
    assert(yeez_decrypt((void *)key,src,16,dst,iv,12,NULL,0,(void *)tag)==SGX_SUCCESS);
    DENY(yeez_cmac((void *)(key+1),src,0,(void *)tag),ENCBOUND_ERR_RANGE);
    DENY(yeez_cmac((void *)key,src,33,(void *)tag),ENCBOUND_ERR_RANGE);
    DENY(yeez_cmac((void *)key,src,0,(void *)(tag+1)),ENCBOUND_ERR_RANGE);
    assert(yeez_cmac((void *)key,src,0,(void *)tag)==SGX_SUCCESS);
    assert(yeez_cmac((void *)key,NULL,0,(void *)tag)==SGX_ERROR_INVALID_PARAMETER);
    DENY(yeez_sha256(src,33,(void *)hash),ENCBOUND_ERR_RANGE);
    DENY(yeez_sha256(src,0,(void *)(hash+1)),ENCBOUND_ERR_RANGE);
    assert(yeez_sha256(src,0,(void *)hash)==SGX_SUCCESS && ((uint8_t *)hr)[0]==0x52);
    assert(yeez_sha256(NULL,0,(void *)hash)==SGX_ERROR_INVALID_PARAMETER);
    DENY(yeez_memset_s(key,17,0,17),ENCBOUND_ERR_RANGE);
    assert(yeez_memset_s(key,16,0,17)==EOVERFLOW);
    state();
    DENY(yeez_dh_init(SGX_DH_SESSION_INITIATOR,(void *)((uintptr_t)session+100)),ENCBOUND_ERR_RANGE);
    assert(yeez_dh_init(SGX_DH_SESSION_INITIATOR,session)==SGX_SUCCESS && ((uint8_t *)session_raw)[0]==0);
    ((sgx_dh_msg1_t *)msg1_raw)->g_a.gx[0]=0x31;state();
    DENY(yeez_dh_msg1((void *)((uintptr_t)m1+512),m2,session),ENCBOUND_ERR_RANGE);
    DENY(yeez_dh_msg1(m1,(void *)((uintptr_t)m2+32),session),ENCBOUND_ERR_RANGE);
    DENY(yeez_dh_msg1(m1,m2,(void *)((uintptr_t)session+100)),ENCBOUND_ERR_RANGE);
    unsigned before=calls;
    assert(yeez_dh_msg1(m1,(void *)m1,session)==SGX_ERROR_INVALID_PARAMETER && calls==before);
    service_status=SGX_ERROR_INVALID_STATE;
    assert(yeez_dh_msg1(m1,m2,session)==service_status && ((uint8_t *)session_raw)[0]==0x21);
    assert(((sgx_dh_msg2_t *)msg2_raw)->g_b.gx[0]==0x32);
    state();assert(yeez_dh_msg1(NULL,NULL,session)==service_status && ((uint8_t *)session_raw)[0]==0x21);
    state();service_status=SGX_SUCCESS;
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=8;expected_tail=8;
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop[7]=0x73;
    DENY(yeez_dh_msg3((void *)((uintptr_t)m3+800),session,aek,identity),ENCBOUND_ERR_RANGE);
    DENY(yeez_dh_msg3(m3,(void *)((uintptr_t)session+100),aek,identity),ENCBOUND_ERR_RANGE);
    DENY(yeez_dh_msg3(m3,session,(void *)((uintptr_t)aek+1),identity),ENCBOUND_ERR_RANGE);
    DENY(yeez_dh_msg3(m3,session,aek,(void *)((uintptr_t)identity+300)),ENCBOUND_ERR_RANGE);
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=800;
    DENY(yeez_dh_msg3(m3,session,aek,identity),ENCBOUND_ERR_RANGE);
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=UINT32_MAX;
    before=calls;assert(yeez_dh_msg3(m3,session,aek,identity)==SGX_ERROR_INVALID_PARAMETER && calls==before);
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=8;
    allocation_failure=1;
    assert(yeez_dh_msg3(m3,session,aek,identity)==SGX_ERROR_OUT_OF_MEMORY && calls==before);
    allocation_failure=0;
    assert(yeez_dh_msg3(m3,session,aek,identity)==SGX_SUCCESS);
    assert(((uint8_t *)session_raw)[0]==0x22 && ((uint8_t *)key_raw)[0]==0x41);
    assert(((sgx_dh_session_enclave_identity_t *)identity_raw)->isv_prod_id==0x42);
    state();service_status=SGX_ERROR_MAC_MISMATCH;
    assert(yeez_dh_msg3(m3,session,aek,identity)==service_status && ((uint8_t *)session_raw)[0]==0x22);
    state();service_status=SGX_SUCCESS;
    /* Outside caller buffer changes length after validation, during allocation. */
    racing_header=malloc(sizeof(*m3)+8);assert(racing_header);
    memcpy(racing_header,mr,sizeof(*m3)+8);
    assert(yeez_dh_msg3(racing_header,session,aek,identity)==SGX_SUCCESS);
    assert(racing_header->msg3_body.additional_prop_length==UINT32_MAX);
    free(racing_header);racing_header=NULL;
    void *trusted=(void *)(encbound_enclave_base()+0x300000);
    DENY(yeez_read_rand(trusted,16),ENCBOUND_ERR_POLICY);
    DENY(yeez_sha256(trusted,16,(void *)hash),ENCBOUND_ERR_POLICY);
    DENY(yeez_dh_init(SGX_DH_SESSION_INITIATOR,trusted),ENCBOUND_ERR_POLICY);
    DENY(yeez_dh_msg1(trusted,m2,session),ENCBOUND_ERR_POLICY);
    DENY(yeez_dh_msg3(trusted,session,aek,identity),ENCBOUND_ERR_POLICY);
#ifdef ENCBOUND_MAC27
    DENY(yeez_read_rand((void *)((uintptr_t)key^(1ull<<32)),16),ENCBOUND_ERR_TAG);
    DENY(yeez_dh_init(SGX_DH_SESSION_INITIATOR,(void *)((uintptr_t)session^(1ull<<32))),ENCBOUND_ERR_TAG);
#endif
    assert(denied>=28);
    printf("YEEZ ADAPTER NATIVE PASS rejections=%u service_calls=%u private_staging/race/exhaustion/errors=pass\n",denied,calls);
    return 0;
}
