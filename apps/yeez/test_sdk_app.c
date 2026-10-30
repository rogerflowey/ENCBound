/* Instrumented application fixture for actual pinned SDK calls in SIM. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "services.h"
#define CHECK(condition) do { if(!(condition))return -__LINE__; } while(0)
extern sgx_status_t yeez_peer_msg1(sgx_dh_msg1_t *,uint32_t);
extern sgx_status_t yeez_peer_msg2(const sgx_dh_msg2_t *,sgx_dh_msg3_t *,size_t);
extern int yeez_peer_key(const sgx_key_128bit_t *);
static unsigned call_count;

static int crypto(void)
{
    const uint8_t sha_expected[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    const uint8_t cipher_expected[16]={0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
    const uint8_t tag_expected[16]={0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
    const uint8_t cmac_expected[16]={0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
    sgx_cmac_128bit_key_t cmac_key={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    sgx_aes_gcm_128bit_key_t key={0};sgx_aes_gcm_128bit_tag_t tag;
    sgx_sha256_hash_t hash;sgx_cmac_128bit_tag_t mac;
    uint8_t iv[12]={0},plain[16]={0},cipher[16],back[16],random[32];
    CHECK(sgx_sha256_msg((const uint8_t *)"abc",3,&hash)==SGX_SUCCESS);
    CHECK(!memcmp(hash,sha_expected,32));
    CHECK(sgx_rijndael128_cmac_msg(&cmac_key,plain,0,&mac)==SGX_SUCCESS);
    CHECK(!memcmp(mac,cmac_expected,16));
    CHECK(sgx_rijndael128GCM_encrypt(&key,plain,16,cipher,iv,12,NULL,0,&tag)==SGX_SUCCESS);
    CHECK(!memcmp(cipher,cipher_expected,16) && !memcmp(tag,tag_expected,16));
    CHECK(sgx_rijndael128GCM_decrypt(&key,cipher,16,back,iv,12,NULL,0,&tag)==SGX_SUCCESS);
    CHECK(!memcmp(back,plain,16));
    tag[0]^=1;
    CHECK(sgx_rijndael128GCM_decrypt(&key,cipher,16,back,iv,12,NULL,0,&tag)==SGX_ERROR_MAC_MISMATCH);
    tag[0]^=1;
    CHECK(sgx_rijndael128GCM_decrypt(&key,cipher,16,back,iv,12,NULL,0,&tag)==SGX_SUCCESS);
    CHECK(sgx_read_rand(random,sizeof random)==SGX_SUCCESS);
    CHECK(memset_s(random,sizeof random,0,sizeof random)==0);
    for(size_t j=0;j<sizeof random;++j)CHECK(random[j]==0);
    return 1;
}
static int handshake(uint32_t props,int bad)
{
    sgx_dh_session_t session;
    sgx_dh_msg1_t msg1;sgx_dh_msg2_t msg2;
    uint8_t storage[sizeof(sgx_dh_msg3_t)+8]={0};
    sgx_dh_msg3_t *msg3=(void *)storage;
    sgx_key_128bit_t key;sgx_dh_session_enclave_identity_t identity;
    CHECK(sgx_dh_init_session(SGX_DH_SESSION_INITIATOR,&session)==SGX_SUCCESS);
    CHECK(yeez_peer_msg1(&msg1,props)==SGX_SUCCESS);
    CHECK(sgx_dh_initiator_proc_msg1(&msg1,&msg2,&session)==SGX_SUCCESS);
    CHECK(yeez_peer_msg2(&msg2,msg3,sizeof storage)==SGX_SUCCESS);
    CHECK(msg3->msg3_body.additional_prop_length==props);
    if(bad)msg3->cmac[0]^=1;
    sgx_status_t status=sgx_dh_initiator_proc_msg3(msg3,&session,&key,&identity);
    /* The pinned DH API converts verification errors to UNEXPECTED. */
    if(bad){CHECK(status==SGX_ERROR_UNEXPECTED);return 1;}
    CHECK(status==SGX_SUCCESS);
    CHECK(yeez_peer_key(&key)==1);
    return 1;
}
int adapter_probe(int action)
{
    CHECK(++call_count!=0);
    if(action==0)return crypto();
    if(action==1)return handshake(0,0);
    if(action==2)return handshake(8,0);
    if(action==3){int v=handshake(8,1);if(v!=1)return v;return handshake(8,0);}
    if(action==4){
        sgx_dh_session_t session;
        sgx_dh_msg1_t m1={0};sgx_dh_msg2_t m2;
        CHECK(sgx_dh_init_session((sgx_dh_session_role_t)9,&session)==SGX_ERROR_INVALID_PARAMETER);
        CHECK(sgx_dh_init_session(SGX_DH_SESSION_RESPONDER,&session)==SGX_SUCCESS);
        CHECK(sgx_dh_initiator_proc_msg1(&m1,&m2,&session)==SGX_ERROR_INVALID_PARAMETER);
        CHECK(sgx_dh_init_session(SGX_DH_SESSION_INITIATOR,&session)==SGX_SUCCESS);
        CHECK(sgx_dh_initiator_proc_msg1(NULL,&m2,&session)==SGX_ERROR_INVALID_PARAMETER);
        return 1;
    }
    if(action==100){uint8_t src[32]={0};sgx_sha256_hash_t out;return sgx_sha256_msg(src,33,&out);}
    if(action==101){sgx_aes_gcm_128bit_key_t key={0};uint8_t src[16]={0},dst[16],iv[12]={0},tag[16];
        return sgx_rijndael128GCM_encrypt(&key,src,16,dst,iv,12,NULL,0,(void *)(tag+1));}
    if(action==102 || action==104){sgx_dh_session_t s;
        uintptr_t p=(uintptr_t)&s;
        p=action==102 ? p+100 : p^(1ull<<32);
        return sgx_dh_init_session(SGX_DH_SESSION_INITIATOR,(void *)p);}
    if(action==103){uint8_t bytes[sizeof(sgx_dh_msg3_t)+8]={0};sgx_dh_msg3_t *m=(void *)bytes;
        sgx_dh_session_t s;sgx_key_128bit_t k;sgx_dh_session_enclave_identity_t i;
        m->msg3_body.additional_prop_length=800;
        return sgx_dh_initiator_proc_msg3(m,&s,&k,&i);}
    return -999;
}
