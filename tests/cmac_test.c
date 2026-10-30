/* Independent OpenSSL oracle for the exact optional trusted CMAC header. */
#include <assert.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "aes_cmac.h"
static uint64_t state=UINT64_C(0xe247d63ca2191740);
static uint64_t next(void){state^=state<<13;state^=state>>7;state^=state<<17;return state;}
int main(void){
 if(!__builtin_cpu_supports("aes"))return 77;
 EVP_MAC *mac=EVP_MAC_fetch(NULL,"CMAC",NULL);assert(mac);EVP_MAC_CTX *ctx=EVP_MAC_CTX_new(mac);assert(ctx);
 char cipher[]="AES-128-CBC";OSSL_PARAM params[]={OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,cipher,0),OSSL_PARAM_construct_end()};
 for(unsigned i=0;i<20000;i++){
  uint64_t k0=next(),k1=next(),bits=next();uint8_t key[16],msg[6],got[16],expected[16];
  if(i<4){k0=k1=(i&1)?UINT64_MAX:0;bits=(i&2)?UINT64_MAX:0;}
  for(unsigned j=0;j<8;j++){key[j]=(uint8_t)(k0>>(8*j));key[j+8]=(uint8_t)(k1>>(8*j));}
  for(unsigned j=0;j<6;j++)msg[j]=(uint8_t)(bits>>(8*j));
  encbound_cmac_context c;encbound_cmac_init(&c,k0,k1);
  size_t n=0;assert(EVP_MAC_init(ctx,key,16,params));assert(EVP_MAC_update(ctx,msg,6));assert(EVP_MAC_final(ctx,expected,&n,16)&&n==16);
  encbound_v128 v=encbound_cmac_full6(&c,msg[0],msg[1],(uint32_t)(bits>>16));memcpy(got,&v,16);assert(!memcmp(got,expected,16));
  uint32_t tag=((uint32_t)expected[0]<<19)|((uint32_t)expected[1]<<11)|((uint32_t)expected[2]<<3)|(expected[3]>>5);
  assert(encbound_cmac27(&c,msg[0],msg[1],(uint32_t)(bits>>16))==tag);
 }
 EVP_MAC_CTX_free(ctx);EVP_MAC_free(mac);puts("CMAC TRUSTED HEADER PASS: 20000 keys/messages, full output and MSB27");
}
