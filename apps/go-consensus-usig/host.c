/* Serial direct-ECALL oracle for the unchanged USIG interface. OpenSSL supplies
 * independent P-256, Ed25519 and HMAC verification. Test keys are public. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sgx_urts.h>
#include "usig_enclave_u.h"
#include "../four_app_permissions.h"

static unsigned calls, ed_verified, ec_verified, mac_verified, logs;
void ocall_print_string(const char *s) { assert(s); ++logs; fprintf(stderr,"USIG: %s\n",s); }
#define CALL(fn,want,...) do { sgx_status_t a=0xdead, t=fn(eid,&a,__VA_ARGS__); ++calls; \
    if(t!=SGX_SUCCESS || a!=(want)) { fprintf(stderr,"FAIL %s:%d transport=%x app=%x expected=%x\n",#fn,__LINE__,t,a,(unsigned)(want));abort(); } } while(0)
static void le64(uint8_t *p,uint64_t x){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(x>>(8*i));}
static void le32(uint8_t *p,uint32_t x){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static void unhex(uint8_t *dst,const char *s){while(*s){unsigned x;assert(sscanf(s,"%2x",&x)==1);*dst++=x;s+=2;}}
static void mac_oracle(const uint8_t *key,size_t n,const uint8_t *digest,uint64_t ctr,uint8_t *expected)
{uint8_t data[40];memcpy(data,digest,32);le64(data+32,ctr);unsigned got;assert(HMAC(EVP_sha256(),key,n,data,sizeof data,expected,&got));assert(got==32);}
static void check_ed(EVP_PKEY *pub,const uint8_t *digest,uint32_t id,uint64_t ctr,const uint8_t *sig)
{
 uint8_t msg[44];le32(msg,id);le64(msg+4,ctr);memcpy(msg+12,digest,32);
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();assert(ctx);assert(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,pub)==1);
 assert(EVP_DigestVerify(ctx,sig,64,msg,sizeof msg)==1);
 msg[43]^=1;assert(EVP_DigestVerify(ctx,sig,64,msg,sizeof msg)!=1);EVP_MD_CTX_free(ctx);++ed_verified;
}
static void check_ec(EC_KEY *pub,const uint8_t *digest,uint64_t ctr,const sgx_ec256_signature_t *sig)
{
 uint8_t msg[40],hash[32];memcpy(msg,digest,32);le64(msg+32,ctr);SHA256(msg,sizeof msg,hash);
 ECDSA_SIG *s=ECDSA_SIG_new();assert(s);BIGNUM *r=BN_lebin2bn((const uint8_t *)sig->x,32,NULL),*v=BN_lebin2bn((const uint8_t *)sig->y,32,NULL);
 assert(r && v && ECDSA_SIG_set0(s,r,v));assert(ECDSA_do_verify(hash,32,s,pub)==1);
 hash[0]^=1;assert(ECDSA_do_verify(hash,32,s,pub)==0);ECDSA_SIG_free(s);++ec_verified;
}
__attribute__((noinline)) void usig_trace_ready(void) { __asm__ volatile("" ::: "memory"); }
int main(int argc,char **argv)
{
 assert(argc>=2);const char *image=argv[1];const char *mode=argc>2?argv[2]:"normal";
 sgx_enclave_id_t eid=0;assert(sgx_create_enclave(image,SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL)==SGX_SUCCESS);
 usig_trace_ready();four_app_permissions(image);
 uint8_t key[1100],sk[1100],pubbytes[32],digest[32],cert[80],sig[80],expected[32],identical;
 memset(key,'K',sizeof key);memset(sk,'S',sizeof sk);
 unhex(sk,"54ba20a8df7259de04c5a0396be3d0796ef1753d6515e9c9d9aea1929632a5b87454ba59d3570463e92f76e8a17a9f38d0c222c31b4a40a625aee1c46d94efb6");
 memcpy(pubbytes,sk+32,32);SHA256((const uint8_t *)"testmessage",11,digest);
 sgx_ec256_private_t private={{1}};sgx_ec256_signature_t ec;
 uint64_t ctr=0,next[3]={1,1,1};
 if(!strcmp(mode,"key-overflow")){CALL(ecall_usig_init,SGX_SUCCESS,(char*)key,1025,private,3,(char*)sk,64);goto done;}
 if(!strcmp(mode,"ed-key-end")){CALL(ecall_usig_init,SGX_SUCCESS,(char*)key,32,private,3,(char*)sk,1024);goto done;}
 if(!strcmp(mode,"allocation-exhaustion")){CALL(ecall_usig_init,SGX_SUCCESS,(char*)key,32,private,0x4000000,(char*)sk,64);goto done;}
 if(!strcmp(mode,"zero-counters")){CALL(ecall_usig_init,SGX_SUCCESS,(char*)key,32,private,0,(char*)sk,64);CALL(ecall_usig_create_ui_mac,SGX_SUCCESS,digest,&ctr,cert,32);goto done;}
 CALL(ecall_usig_create_ui_sig,SGX_ERROR_UNEXPECTED,digest,&ctr,&ec);
 CALL(ecall_usig_create_ui_mac,SGX_ERROR_UNEXPECTED,digest,&ctr,cert,32);
 CALL(ecall_usig_verify_ui_mac,SGX_ERROR_UNEXPECTED,digest,1,cert,32,&identical);
 CALL(ecall_usig_create_ui_sig_edd25519,SGX_ERROR_UNEXPECTED,digest,0,&ctr,sig,64);
 CALL(ecall_usig_init,SGX_SUCCESS,(char*)key,32,private,3,(char*)sk,64);
 if(!strcmp(mode,"bad-counter")){CALL(ecall_usig_create_ui_sig_edd25519,SGX_SUCCESS,digest,4,&ctr,sig,64);goto done;}
 CALL(ecall_usig_init,SGX_ERROR_UNEXPECTED,(char*)key,32,private,1,(char*)sk,64);
 EC_KEY *ecpub=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);assert(ecpub);
 const EC_GROUP *group=EC_KEY_get0_group(ecpub);EC_POINT *point=EC_POINT_new(group);BIGNUM *one=BN_new();BN_one(one);
 assert(EC_POINT_mul(group,point,one,NULL,NULL,NULL));assert(EC_KEY_set_public_key(ecpub,point));EC_POINT_free(point);BN_free(one);
 EVP_PKEY *edpub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,pubbytes,32);assert(edpub);
 for(unsigned round=0;round<6;round++) {
  for(unsigned i=0;i<32;i++)digest[i]=(uint8_t)(round*37+i*13);
  for(unsigned id=0;id<3;id++){
   memset(sig,0xcc,sizeof sig);CALL(ecall_usig_create_ui_sig_edd25519,SGX_SUCCESS,digest,id,&ctr,sig,64);assert(ctr==next[id]++);
   check_ed(edpub,digest,id,ctr,sig);for(unsigned i=64;i<sizeof sig;i++)assert(sig[i]==0xcc);
  }
  CALL(ecall_usig_create_ui_sig,SGX_SUCCESS,digest,&ctr,&ec);assert(ctr==next[0]++);check_ec(ecpub,digest,ctr,&ec);
  memset(cert,0xcc,sizeof cert);CALL(ecall_usig_create_ui_mac,SGX_SUCCESS,digest,&ctr,cert,32);assert(ctr==next[0]++);
  mac_oracle(key,32,digest,ctr,expected);assert(!memcmp(cert,expected,32));for(unsigned i=32;i<sizeof cert;i++)assert(cert[i]==0xcc);++mac_verified;
  identical=0;CALL(ecall_usig_verify_ui_mac,SGX_SUCCESS,digest,ctr,cert,32,&identical);assert(identical==1);
  cert[0]^=1;CALL(ecall_usig_verify_ui_mac,SGX_SUCCESS,digest,ctr,cert,32,&identical);assert(identical==0);cert[0]^=1;
  CALL(ecall_usig_verify_ui_mac,SGX_SUCCESS,digest,ctr+1,cert,32,&identical);assert(identical==0);
  digest[0]^=1;CALL(ecall_usig_verify_ui_mac,SGX_SUCCESS,digest,ctr,cert,32,&identical);assert(identical==0);digest[0]^=1;
 }
 /* IPP permits truncated HMAC lengths 1..32; error cleanup for 33 is observable. */
 for(unsigned n=1;n<=32;n+=7){
  memset(cert,0xcc,sizeof cert);CALL(ecall_usig_create_ui_mac,SGX_SUCCESS,digest,&ctr,cert,n);assert(ctr==next[0]++);
  mac_oracle(key,32,digest,ctr,expected);assert(!memcmp(cert,expected,n));assert(cert[n]==0xcc);++mac_verified;
  CALL(ecall_usig_verify_ui_mac,SGX_SUCCESS,digest,ctr,cert,n,&identical);assert(identical==1);
 }
 memset(cert,0xcc,sizeof cert);CALL(ecall_usig_create_ui_mac,SGX_ERROR_UNEXPECTED,digest,&ctr,cert,33);assert(ctr==next[0]++);
 for(unsigned i=0;i<33;i++)assert(cert[i]==0);assert(cert[33]==0xcc);
 CALL(ecall_usig_verify_ui_mac,SGX_ERROR_UNEXPECTED,digest,ctr,cert,33,&identical);
 CALL(ecall_usig_create_ui_mac,SGX_ERROR_INVALID_PARAMETER,digest,&ctr,cert,0);assert(ctr==next[0]++);
 CALL(ecall_usig_verify_ui_mac,SGX_ERROR_INVALID_PARAMETER,digest,ctr,cert,0,&identical);
 for(unsigned n=63;n<=65;n+=2){
  memset(sig,0xcc,sizeof sig);CALL(ecall_usig_create_ui_sig_edd25519,SGX_ERROR_UNEXPECTED,digest,1,&ctr,sig,n);assert(ctr==next[1]++);
  for(unsigned i=0;i<n;i++)assert(sig[i]==0);assert(sig[n]==0xcc);
 }
 CALL(ecall_usig_create_ui_sig_edd25519,SGX_SUCCESS,digest,1,&ctr,sig,64);assert(ctr==next[1]++);check_ed(edpub,digest,1,ctr,sig);
 CALL(ecall_usig_create_ui_sig,SGX_SUCCESS,digest,&ctr,&ec);assert(ctr==next[0]++);check_ec(ecpub,digest,ctr,&ec);
 CALL(ecall_usig_create_ui_mac,SGX_SUCCESS,digest,&ctr,cert,32);assert(ctr==next[0]++);mac_oracle(key,32,digest,ctr,expected);assert(!memcmp(cert,expected,32));++mac_verified;
 EVP_PKEY_free(edpub);EC_KEY_free(ecpub);assert(logs==2);
 /* A second enclave checks binary-key strncpy semantics without changing source:
  * an embedded NUL zero-pads the rest of the HMAC key. */
 assert(sgx_destroy_enclave(eid)==SGX_SUCCESS);assert(sgx_create_enclave(image,SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL)==SGX_SUCCESS);
 key[5]=0;CALL(ecall_usig_init,SGX_SUCCESS,(char*)key,32,private,1,(char*)sk,64);
 CALL(ecall_usig_create_ui_mac,SGX_SUCCESS,digest,&ctr,cert,32);assert(ctr==1);
 memset(key+5,0,27);mac_oracle(key,32,digest,ctr,expected);assert(!memcmp(cert,expected,32));++mac_verified;
 done:
 assert(sgx_destroy_enclave(eid)==SGX_SUCCESS);
 printf("PASS mode=%s ecalls=%u ed25519=%u ecdsa=%u hmac=%u logs=%u\n",mode,calls,ed_verified,ec_verified,mac_verified,logs);
 return 0;
}
