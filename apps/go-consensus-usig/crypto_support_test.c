/* Native functional controls for the two supplied application crypto helpers.
 * Random bytes are deterministic SDK stand-ins, not an entropy-quality test. */
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sgx_trts.h>
#include "edd25519/crypto_api.h"
static int fail_random;
static unsigned calls;
sgx_status_t sgx_read_rand(unsigned char *p,size_t n)
{
 ++calls;if(fail_random)return SGX_ERROR_UNEXPECTED;
 memset(p,0x5a,n);return SGX_SUCCESS;
}
int main(void)
{
 struct rlimit none={0,0};assert(!setrlimit(RLIMIT_CORE,&none));
 unsigned char a[32],b[32],c[37];
 memset(a,0x80,32);memcpy(b,a,32);assert(crypto_verify_32(a,b)==0);
 for(unsigned i=0;i<32;i++){
  b[i]^=1;assert(crypto_verify_32(a,b)==-1);assert(crypto_verify_32(b,a)==-1);b[i]^=1;
 }
 memset(a,0,32);memset(b,255,32);assert(crypto_verify_32(a,b)==-1);
 memset(c,0xcc,sizeof c);randombytes(c+1,35);assert(calls==1 && c[0]==0xcc && c[36]==0xcc);
 for(unsigned i=1;i<=35;i++)assert(c[i]==0x5a);
 randombytes(NULL,0);assert(calls==1);
 pid_t child=fork();assert(child>=0);
 if(!child){fail_random=1;randombytes(c,1);_Exit(17);}
 int status;assert(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT);
 puts("USIG CRYPTO HELPERS PASS: equal/different vectors, every byte, random extent/zero/error");
 return 0;
}
