/* Native real ENCBound runtime with recording SDK stand-ins. These test range,
 * access kind, decoding, and pre-call rejection; cryptographic behavior is
 * exercised separately with the real SDK in the SIM session. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sgx_tcrypto.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "fake_platform.h"
#include "test_harness.h"

extern sgx_status_t encbound_oblidb_rand(unsigned char *,size_t);
extern sgx_status_t encbound_oblidb_encrypt(const sgx_aes_gcm_128bit_key_t *,const uint8_t *,uint32_t,
    uint8_t *,const uint8_t *,uint32_t,const uint8_t *,uint32_t,sgx_aes_gcm_128bit_tag_t *);
extern sgx_status_t encbound_oblidb_decrypt(const sgx_aes_gcm_128bit_key_t *,const uint8_t *,uint32_t,
    uint8_t *,const uint8_t *,uint32_t,const uint8_t *,uint32_t,const sgx_aes_gcm_128bit_tag_t *);
static unsigned sdk_calls;
static sgx_status_t sdk_status;
static void *raws[6];
static unsigned aad_bytes=8;
sgx_status_t sgx_read_rand(unsigned char *p,size_t n) {
    ++sdk_calls;CHECK(p==raws[2]);CHECK_EQ(n,16);
    if(!sdk_status)memset(p,0xa5,n);
    return sdk_status;
}
static sgx_status_t record(const void *k,const void *s,uint32_t n,void *d,
    const void *v,uint32_t vl,const void *a,uint32_t al,const void *t,int decrypt) {
    ++sdk_calls;
    CHECK(k==raws[0]);CHECK(s==raws[1]);CHECK(d==raws[2]);CHECK(v==raws[3]);
    CHECK(a==(aad_bytes?raws[4]:NULL));CHECK(t==raws[5]);
    CHECK_EQ(n,16);CHECK_EQ(vl,12);CHECK_EQ(al,aad_bytes);
    if(!sdk_status) {
        memcpy(d,s,n);
        if(!decrypt)memset((void *)t,0x55,16);
    }
    return sdk_status;
}
sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *k,
    const uint8_t *s,uint32_t n,uint8_t *d,const uint8_t *v,uint32_t vl,
    const uint8_t *a,uint32_t al,sgx_aes_gcm_128bit_tag_t *t) {
    return record(k,s,n,d,v,vl,a,al,t,0);
}
sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *k,
    const uint8_t *s,uint32_t n,uint8_t *d,const uint8_t *v,uint32_t vl,
    const uint8_t *a,uint32_t al,const sgx_aes_gcm_128bit_tag_t *t) {
    return record(k,s,n,d,v,vl,a,al,t,1);
}
#define REJECT(code,expr) do { \
    unsigned before=sdk_calls;fake_abort_active=1; \
    if(setjmp(fake_abort_env)==0){(void)(expr);CHECK(0);} \
    else {CHECK_EQ(fake_abort_code,(code));} \
    fake_abort_active=0;CHECK_EQ(sdk_calls,before); \
} while(0)
static sgx_status_t call(int decrypt,uint8_t **p,unsigned n,unsigned ivlen,unsigned aadlen) {
    if(decrypt)return encbound_oblidb_decrypt((void *)p[0],p[1],n,p[2],p[3],ivlen,p[4],aadlen,(void *)p[5]);
    return encbound_oblidb_encrypt((void *)p[0],p[1],n,p[2],p[3],ivlen,p[4],aadlen,(void *)p[5]);
}
int main(void) {
    CHECK_EQ(encbound_runtime_init_with_key(0x0706050403020100ULL,0x0f0e0d0c0b0a0908ULL),ENCBOUND_OK);
    uint8_t *p[6],*saved[6];
    for(int i=0;i<6;++i) {
        p[i]=saved[i]=encbound_malloc(16);CHECK(p[i]!=NULL);
        raws[i]=(void *)encbound_require((uintptr_t)p[i],16,ENCBOUND_ACCESS_WRITE);
        memset(raws[i],i+1,16);
    }
    CHECK_EQ(encbound_oblidb_rand(p[2],16),0);
    CHECK_EQ(((uint8_t *)raws[2])[15],0xa5);
    REJECT(ENCBOUND_ERR_RANGE,encbound_oblidb_rand(p[2]+1,16));
    REJECT(ENCBOUND_ERR_POLICY,encbound_oblidb_rand(raws[2],16));
    unsigned before=sdk_calls;
    CHECK_EQ(encbound_oblidb_rand(NULL,16),SGX_ERROR_INVALID_PARAMETER);
    CHECK_EQ(encbound_oblidb_rand(p[2],0),SGX_ERROR_INVALID_PARAMETER);
    CHECK_EQ(sdk_calls,before);
    for(int decrypt=0;decrypt<2;++decrypt) {
        CHECK_EQ(call(decrypt,p,16,12,8),0);
        CHECK(!memcmp(raws[1],raws[2],16));
        CHECK_EQ(((uint8_t *)raws[5])[15],0x55);
        sdk_status=SGX_ERROR_MAC_MISMATCH;
        CHECK_EQ(call(decrypt,p,16,12,8),SGX_ERROR_MAC_MISMATCH);
        sdk_status=0;
        for(int i=0;i<6;++i) {
            p[i]+=i==3?8:i==4?12:1;
            REJECT(ENCBOUND_ERR_RANGE,call(decrypt,p,16,12,8));
            p[i]=raws[i];
            REJECT(ENCBOUND_ERR_POLICY,call(decrypt,p,16,12,8));
#ifdef ENCBOUND_MAC27
            p[i]=(void *)((uintptr_t)saved[i]^(1ULL<<ENCBOUND_TAG_SHIFT));
            REJECT(ENCBOUND_ERR_TAG,call(decrypt,p,16,12,8));
#endif
            p[i]=saved[i];
        }
        before=sdk_calls;
        CHECK_EQ(call(decrypt,p,0,12,8),SGX_ERROR_INVALID_PARAMETER);
        CHECK_EQ(call(decrypt,p,16,11,8),SGX_ERROR_INVALID_PARAMETER);
        for(int i=0;i<6;++i) {
            p[i]=NULL;CHECK_EQ(call(decrypt,p,16,12,8),SGX_ERROR_INVALID_PARAMETER);p[i]=saved[i];
        }
        CHECK_EQ(sdk_calls,before);
        aad_bytes=0;p[4]=(void *)1;
        CHECK_EQ(call(decrypt,p,16,12,0),0);
        p[4]=saved[4];aad_bytes=8;
    }
    // The same adapters admit real outside-enclave buffers without minting.
    uint8_t host[6][16];
    for(int i=0;i<6;++i){p[i]=host[i];raws[i]=host[i];memset(host[i],i+1,16);}
    CHECK_EQ(call(0,p,16,12,8),0);CHECK_EQ(call(1,p,16,12,8),0);
    for(int i=0;i<6;++i)encbound_free(saved[i]);
    return TEST_SUMMARY("oblidb_crypto");
}
