/* Trusted unit controls for dynamic-stack arithmetic, geometry and headroom. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "fake_platform.h"
static uintptr_t low,high;
static void negative(unsigned which,int expected) {
    fake_abort_active=1;
    if (!setjmp(fake_abort_env)) {
        switch(which) {
        case 0: encbound_stack_prepare((void *)(low+16384+64-1),17,1,16);break;
        case 1: encbound_stack_prepare((void *)high,0,1,16);break;
        case 2: encbound_stack_prepare((void *)high,SIZE_MAX,4,16);break;
        case 3: encbound_stack_prepare((void *)high,1,1,3);break;
        case 4: encbound_stack_prepare((void *)(low+0x1000000),1,1,16);break;
        case 5: encbound_stack_mint_dynamic((void *)(low+0x1000000),32);break;
        case 6: encbound_stack_mint_dynamic((void *)(high-32),32);break;
        case 7: encbound_stack_mint_dynamic((void *)low,31);break;
        case 8: encbound_stack_product(SIZE_MAX,3);break;
        case 9: encbound_stack_product(1ul<<30,2);break;
        case 10:encbound_stack_prepare((void *)high,1,0,16);break;
        case 11:encbound_stack_prepare((void *)(encbound_enclave_base()-1),1,1,16);break;
        }
        assert(!"invalid protocol request returned");
    } else assert(fake_abort_code==expected);
    fake_abort_active=0;
}
int main(void) {
    assert(encbound_runtime_init_with_key(11,22)==0);
    low=encbound_enclave_base()+0x100000;high=low+0x100000;
    assert(encbound_stack_prepare((void *)high,17,1,16)==32);
    assert(encbound_stack_prepare((void *)high,1,1,256)==256);
    assert(encbound_stack_prepare((void *)(low+16384+64),17,1,16)==32);
    assert(encbound_stack_product(17,7)==119);
    for (unsigned c=0;c<12;++c)
        negative(c,c==4 || c==5 || c==6 || c==11 ? ENCBOUND_ERR_POLICY : ENCBOUND_ERR_ALLOC);
    uintptr_t raw=low+17,decoded=0;size_t extent=0;
    memset((void *)raw,0xa5,64);
    uintptr_t cap=encbound_stack_mint_dynamic((void *)raw,32);
    assert(encbound_check_extent(cap,&decoded,&extent)==0 && decoded==low+32 && extent==32);
    for (unsigned i=0;i<32;++i)assert(((unsigned char *)decoded)[i]==0);
    assert(*(unsigned char *)raw==0xa5 && *(unsigned char *)(decoded+32)==0xa5);
    puts("VLA PROTOCOL PASS: headroom threshold, aligned interior, clearing, 12 attributed controls");
    return 0;
}
