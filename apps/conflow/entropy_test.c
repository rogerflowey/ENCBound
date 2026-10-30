/* Real native runtime; recording sgx_read_rand stand-in checks decoded writes
 * and proves invalid spans reject before invoking the SDK service. */
#include <stdint.h>
#include <string.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "fake_platform.h"
#include "test_harness.h"
extern uint32_t encbound_conflow_rand(unsigned char *, size_t);
static unsigned sdk_calls;
static uint32_t sdk_status;
uint32_t sgx_read_rand(unsigned char *p,size_t n) {
    ++sdk_calls;
    if(n && !sdk_status)memset(p,0xa5,n);
    return sdk_status;
}
#define REJECT(code,ptr,n) do { \
    unsigned before=sdk_calls; fake_abort_active=1; \
    if(setjmp(fake_abort_env)==0) { (void)encbound_conflow_rand((void *)(ptr),(n));CHECK(0); } \
    else {CHECK_EQ(fake_abort_code,(code));} \
    fake_abort_active=0; CHECK_EQ(sdk_calls,before); \
} while(0)
int main(void) {
    CHECK_EQ(encbound_runtime_init_with_key(0x0706050403020100ULL,0x0f0e0d0c0b0a0908ULL),ENCBOUND_OK);
    unsigned char *p=encbound_malloc(16);
    CHECK(p!=NULL);
    unsigned char *raw=(void *)encbound_require((uintptr_t)p,16,ENCBOUND_ACCESS_WRITE);
    memset(raw,0,16);
    CHECK_EQ(encbound_conflow_rand(p,16),0);
    CHECK_EQ(raw[0],0xa5);CHECK_EQ(raw[15],0xa5);
    raw[0]=raw[15]=0;
    CHECK_EQ(encbound_conflow_rand(p+1,14),0);
    CHECK_EQ(raw[0],0);CHECK_EQ(raw[15],0);CHECK_EQ(raw[1],0xa5);
    unsigned char host[8]={0};
    CHECK_EQ(encbound_conflow_rand(host,8),0);CHECK_EQ(host[7],0xa5);
    sdk_status=0x1234;
    CHECK_EQ(encbound_conflow_rand(p,4),0x1234);CHECK_EQ(raw[0],0);
    sdk_status=0;
    REJECT(ENCBOUND_ERR_RANGE,p+12,8);
    REJECT(ENCBOUND_ERR_POLICY,raw,1);
    REJECT(ENCBOUND_ERR_POLICY,encbound_enclave_base()+0x300000,1);
#ifdef ENCBOUND_MAC27
    REJECT(ENCBOUND_ERR_TAG,(uintptr_t)p^(1ULL<<ENCBOUND_TAG_SHIFT),1);
#endif
    encbound_free(p);
    return TEST_SUMMARY("conflow_entropy");
}
