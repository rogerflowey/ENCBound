/* Independent functional oracle for all original sk-sgx ECALLs and provider.
 * OpenSSL verifies every successful Ed25519 signature over the full SK data.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sgx_urts.h>
#include <sgx_tseal.h>
#include "sk-api.h"
#include "sk_u.h"
#include "../four_app_permissions.h"

static unsigned calls, signatures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
#define ECALL(expected, expression) do { int r = 777; sgx_status_t s = (expression); ++calls; if(s!=SGX_SUCCESS || r!=(expected)) fprintf(stderr,"ECALL line %d status=%#x result=%d expected=%d app_len=%zu\n",__LINE__,s,r,expected,strlen(app)); CHECK(s == SGX_SUCCESS); CHECK(r == (expected)); } while (0)

static void verify(const uint8_t *pk, const uint8_t *sig, const char *app,
                   uint8_t flags, uint32_t counter, const uint8_t *msg)
{
    uint8_t data[69];
    SHA256((const unsigned char *)app, strlen(app), data);
    data[32]=flags;
    data[33]=(uint8_t)(counter>>24); data[34]=(uint8_t)(counter>>16);
    data[35]=(uint8_t)(counter>>8); data[36]=(uint8_t)counter;
    memcpy(data+37,msg,32);
    EVP_PKEY *key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,pk,32);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    CHECK(key && ctx);
    CHECK(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1);
    CHECK(EVP_DigestVerify(ctx,sig,64,data,sizeof(data))==1);
    data[68]^=1;
    CHECK(EVP_DigestVerify(ctx,sig,64,data,sizeof(data))==0);
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    ++signatures;
}

static void session(const char *app)
{
    sgx_enclave_id_t eid=0;
    size_t size=0;
    uint8_t pk[32], msg[32], sig[64], previous[64];
    uint32_t counter=0xffffffffU;
    for(unsigned i=0;i<32;++i) msg[i]=(uint8_t)(i*17);
    CHECK(sgx_create_enclave("enclave.signed.so",SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL)==SGX_SUCCESS);
    four_app_permissions("enclave.signed.so");
    ECALL(0,ecall_sk_get_key_handle_len_ed25519(eid,&r,app,&size));
    CHECK(size==sizeof(sgx_sealed_data_t)+64+strlen(app));
    uint8_t *handle=calloc(1,size), *bad=calloc(1,size);
    CHECK(handle && bad);
    /* The original EDL permits null unique pointers; the application rejects
     * them with -1 while the SDK call itself succeeds. */
    ECALL(-1,ecall_sk_get_key_handle_len_ed25519(eid,&r,NULL,&size));
    ECALL(-1,ecall_sk_get_key_handle_len_ed25519(eid,&r,app,NULL));
    ECALL(0,ecall_sk_get_key_handle_len_ed25519(eid,&r,app,&size));
    ECALL(-1,ecall_sk_enroll_ed25519(eid,&r,app,pk,31,handle,size));
    ECALL(-1,ecall_sk_enroll_ed25519(eid,&r,app,pk,32,handle,size-1));
    ECALL(0,ecall_sk_enroll_ed25519(eid,&r,app,pk,32,handle,size));
    if (strlen(app)==6) {
        /* Deliberately exceed both the baseline trusted heap and protected
         * arena, then prove that the same enclave serves successful requests. */
        size_t demand=64*1024*1024;
        uint8_t *large=malloc(demand); CHECK(large);
        int rejected=777;
        CHECK(ecall_sk_enroll_ed25519(eid,&rejected,app,pk,32,large,demand)==SGX_ERROR_OUT_OF_MEMORY);
        ++calls; free(large);
    }
    ECALL(-1,ecall_sk_sign_ed25519(eid,&r,msg,31,app,handle,size,1,&counter,sig,64));
    for(unsigned i=0;i<3;++i) {
        ECALL(0,ecall_sk_sign_ed25519(eid,&r,msg,32,app,handle,size,1,&counter,sig,64));
        CHECK(counter==0); /* original EDL marks this cell [out] */
        verify(pk,sig,app,1,counter,msg);
        if(i) CHECK(memcmp(sig,previous,64)==0);
        memcpy(previous,sig,64);
    }
    memcpy(bad,handle,size); bad[size-1]^=1;
    ECALL(-1,ecall_sk_sign_ed25519(eid,&r,msg,32,app,bad,size,1,&counter,sig,64));
    ECALL(-1,ecall_sk_sign_ed25519(eid,&r,msg,32,app,handle,size,1,&counter,sig,63));
    ECALL(-1,ecall_sk_sign_ed25519(eid,&r,msg,32,app,handle,size-1,1,&counter,sig,64));
    msg[0]^=0xff;
    ECALL(0,ecall_sk_sign_ed25519(eid,&r,msg,32,app,handle,size,4,&counter,sig,64));
    verify(pk,sig,app,4,counter,msg);
    if(strlen(app)) {
        char *wrong=strdup(app); CHECK(wrong); wrong[0]^=1;
        ECALL(-1,ecall_sk_sign_ed25519(eid,&r,msg,32,wrong,handle,size,4,&counter,sig,64));
        free(wrong);
    }
    ECALL(0,ecall_sk_sign_ed25519(eid,&r,msg,32,app,handle,size,0,&counter,sig,64));
    verify(pk,sig,app,0,counter,msg);
    CHECK(sgx_destroy_enclave(eid)==SGX_SUCCESS);
    free(handle); free(bad);
}

static void provider(void)
{
    struct sk_enroll_response *e=NULL;
    struct sk_sign_response *s=NULL;
    uint8_t challenge[32]={0}, msg[32]={0};
    CHECK(sk_api_version()==0x00040000);
    CHECK(sk_enroll(SSH_SK_ED25519,challenge,32,"ssh:test",1,NULL,NULL,&e)==0);
    CHECK(e && e->public_key_len==32 && e->key_handle_len==sizeof(sgx_sealed_data_t)+64+8);
    CHECK(sk_sign(SSH_SK_ED25519,msg,32,"ssh:test",e->key_handle,e->key_handle_len,1,NULL,NULL,&s)==0);
    CHECK(s && s->sig_r_len==64 && s->flags==1 && s->counter==0);
    verify(e->public_key,s->sig_r,"ssh:test",s->flags,s->counter,msg);
    free(s->sig_r); free(s->sig_s); free(s);
    free(e->public_key); free(e->key_handle); free(e->signature); free(e->attestation_cert); free(e);
    CHECK(sk_load_resident_keys(NULL,NULL,NULL,NULL)==SSH_SK_ERR_UNSUPPORTED);
}

int main(void)
{
    char longapp[4097]; memset(longapp,'a',4096); longapp[4096]=0;
    session(""); session("markus"); session("ssh:example.test"); session(longapp);
    provider();
    printf("PASS ecalls=%u verified_signatures=%u provider=original-v4 max_application=4096\n",calls,signatures);
    return 0;
}
