/* Native real-runtime contract controls. SDK stand-ins record calls and touch
 * decoded buffers. Real crypto behavior is checked by the separate SIM oracle. */
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "adapters.h"
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
#include "test_harness.h"
static unsigned raw_calls, live, open_fails, close_fails;
static char sdk_context[4];
#define REJECT(code, expression) do { unsigned before=raw_calls; fake_abort_active=1; \
 if(setjmp(fake_abort_env)==0){(void)(expression);CHECK(0);}else{CHECK_EQ(fake_abort_code,code);} \
 fake_abort_active=0;CHECK_EQ(raw_calls,before); }while(0)
static uint8_t *raw(void *p,size_t n){return (uint8_t *)encbound_require((uintptr_t)p,n,ENCBOUND_ACCESS_READWRITE);}
sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t *out)
{
 ++raw_calls;if(open_fails)return SGX_ERROR_OUT_OF_MEMORY;
 for(unsigned i=0;i<4;i++)if(!(live&(1u<<i))){live|=1u<<i;*out=sdk_context+i;return SGX_SUCCESS;}
 CHECK(0);return SGX_ERROR_UNEXPECTED;
}
sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t h)
{
 ++raw_calls;if(close_fails)return SGX_ERROR_UNEXPECTED;
 uintptr_t index=(uintptr_t)h-(uintptr_t)sdk_context;CHECK(index<4 && (live&(1u<<index)));live&=~(1u<<index);return SGX_SUCCESS;
}
sgx_status_t sgx_ecdsa_sign(const uint8_t *p,uint32_t n,const sgx_ec256_private_t *k,sgx_ec256_signature_t *s,sgx_ecc_state_handle_t h)
{
 ++raw_calls;CHECK((uintptr_t)h>=(uintptr_t)sdk_context && (uintptr_t)h<(uintptr_t)sdk_context+4);
 memset(s, p[0]^p[n-1]^k->r[0]^k->r[31], sizeof(*s));return SGX_SUCCESS;
}
sgx_status_t sgx_hmac_sha256_msg(const unsigned char *p,int n,const unsigned char *k,int kn,unsigned char *m,int mn)
{
 ++raw_calls;CHECK(n>0 && kn>0 && mn>0);
 if(mn>32){memset(m,0,mn);return SGX_ERROR_UNEXPECTED;}
 memset(m,p[0]^p[n-1]^k[0]^k[kn-1],mn);return SGX_SUCCESS;
}
sgx_status_t sgx_read_rand(unsigned char *p,size_t n){++raw_calls;memset(p,0xa5,n);return SGX_SUCCESS;}
int main(void)
{
 CHECK_EQ(encbound_runtime_init_with_key(0x0706050403020100ULL,0x0f0e0d0c0b0a0908ULL),ENCBOUND_OK);
 uint8_t *data=encbound_malloc(64),*key=encbound_malloc(32),*sig=encbound_malloc(64),*cell=encbound_malloc(16);
 CHECK(data && key && sig && cell);
 memset(raw(data,64),1,64);memset(raw(key,32),2,32);raw(data,64)[63]=3;raw(key,32)[31]=4;
 CHECK_EQ(encbound_usig_ecc_open(NULL),SGX_ERROR_INVALID_PARAMETER);
 memset(raw(cell,16),0xcc,16);open_fails=1;
 CHECK_EQ(encbound_usig_ecc_open((void*)cell),SGX_ERROR_OUT_OF_MEMORY);CHECK(raw(cell,16)[0]==0xcc);open_fails=0;
 sgx_ecc_state_handle_t handles[4];
 for(unsigned i=0;i<4;i++){CHECK_EQ(encbound_usig_ecc_open((void*)cell),SGX_SUCCESS);memcpy(handles+i,raw(cell,8),8);CHECK((uintptr_t)handles[i]==i+1);}
 unsigned before=raw_calls;CHECK_EQ(encbound_usig_ecc_open((void*)cell),SGX_ERROR_OUT_OF_MEMORY);CHECK_EQ(raw_calls,before);
 CHECK_EQ(encbound_usig_ecc_close(NULL),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_ecc_close((void*)99),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_ecc_close(sdk_context),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_ecdsa_sign(data,64,(void*)key,(void*)sig,handles[0]),SGX_SUCCESS);CHECK(raw(sig,64)[63]==(1^3^2^4));
 CHECK_EQ(encbound_usig_ecdsa_sign(NULL,64,(void*)key,(void*)sig,handles[0]),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_ecdsa_sign(data,0,(void*)key,(void*)sig,handles[0]),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_ecdsa_sign(data,64,(void*)key,(void*)sig,sdk_context),SGX_ERROR_INVALID_PARAMETER);
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_ecdsa_sign(data+60,8,(void*)key,(void*)sig,handles[0]));
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_ecdsa_sign(data,64,(void*)(key+1),(void*)sig,handles[0]));
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_ecdsa_sign(data,64,(void*)key,(void*)(sig+1),handles[0]));
 close_fails=1;CHECK_EQ(encbound_usig_ecc_close(handles[0]),SGX_ERROR_UNEXPECTED);close_fails=0;
 CHECK_EQ(encbound_usig_ecdsa_sign(data,64,(void*)key,(void*)sig,handles[0]),SGX_SUCCESS);
 for(unsigned i=0;i<4;i++)CHECK_EQ(encbound_usig_ecc_close(handles[i]),SGX_SUCCESS);
 CHECK_EQ(live,0);CHECK_EQ(encbound_usig_ecc_close(handles[0]),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_ecdsa_sign(data,64,(void*)key,(void*)sig,handles[0]),SGX_ERROR_INVALID_PARAMETER);
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_ecc_open((void*)(cell+12)));
 CHECK_EQ(encbound_usig_ecc_open((void*)cell),SGX_SUCCESS);memcpy(handles,raw(cell,8),8);CHECK_EQ(encbound_usig_ecc_close(handles[0]),SGX_SUCCESS);
 CHECK_EQ(encbound_usig_hmac(data,64,key,32,sig,32),SGX_SUCCESS);CHECK(raw(sig,64)[31]==(1^3^2^4));
 CHECK_EQ(encbound_usig_hmac(data+60,4,key+28,4,sig+60,4),SGX_SUCCESS);
 CHECK_EQ(encbound_usig_hmac(data,64,key,32,sig,33),SGX_ERROR_UNEXPECTED);CHECK(raw(sig,64)[32]==0);
 before=raw_calls;
 CHECK_EQ(encbound_usig_hmac(NULL,64,key,32,sig,32),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_hmac(data,0,key,32,sig,32),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_hmac(data,-1,key,32,sig,32),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_hmac(data,64,key,-1,sig,32),SGX_ERROR_INVALID_PARAMETER);
 CHECK_EQ(encbound_usig_hmac(data,64,key,32,sig,-1),SGX_ERROR_INVALID_PARAMETER);CHECK_EQ(raw_calls,before);
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_hmac(data+60,8,key,32,sig,32));
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_hmac(data,64,key+30,4,sig,32));
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_hmac(data,64,key,32,sig+60,8));
 void *stripped=(void*)encbound_require((uintptr_t)data,1,ENCBOUND_ACCESS_READ);
 REJECT(ENCBOUND_ERR_POLICY,encbound_usig_hmac(stripped,64,key,32,sig,32));
 REJECT(ENCBOUND_ERR_POLICY,encbound_usig_ecc_open(stripped));
 uintptr_t trusted=encbound_enclave_base()+0x2000; /* Fake platform private data. */
 REJECT(ENCBOUND_ERR_POLICY,encbound_usig_rand((void*)trusted,1));
 CHECK_EQ(encbound_usig_rand(sig+60,4),SGX_SUCCESS);CHECK(raw(sig,64)[63]==0xa5);
 CHECK_EQ(encbound_usig_rand(NULL,0),SGX_ERROR_INVALID_PARAMETER);
 REJECT(ENCBOUND_ERR_RANGE,encbound_usig_rand(sig+60,8));
#ifdef ENCBOUND_MAC27
 void *forged=(void*)((uintptr_t)data^(1ULL<<ENCBOUND_TAG_SHIFT));
 REJECT(ENCBOUND_ERR_TAG,encbound_usig_hmac(forged,64,key,32,sig,32));
#endif
 encbound_free(data);encbound_free(key);encbound_free(sig);encbound_free(cell);CHECK_EQ(live,0);
 return TEST_SUMMARY("usig_adapters_test");
}
