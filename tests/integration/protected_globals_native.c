/* Native test platform over the actual linked image. No SGX isolation claim. */
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
extern char __executable_start[], __encbound_globalrw_start[], __encbound_globalrw_end[];
extern char __encbound_globalbss_start[], __encbound_globalbss_end[];
extern uintptr_t __encbound_gcaps_start[], __encbound_gcaps_end[];
static unsigned char heap[1<<20] __attribute__((aligned(1<<20)));
static encbound_region_t regions[8]; static size_t count;
static jmp_buf stop;
static void region(uintptr_t lo,uintptr_t hi,unsigned policy,unsigned domain) {
    if (lo==hi) return;
    assert(hi>lo);
    regions[count++]=(encbound_region_t){lo-(uintptr_t)__executable_start,hi-lo,policy,domain};
}
int encbound_platform_init(void) {
    if(count)return 0;
    uintptr_t base=(uintptr_t)__executable_start;
    uintptr_t rw=(uintptr_t)__encbound_globalrw_start,re=(uintptr_t)__encbound_globalrw_end;
    uintptr_t bs=(uintptr_t)__encbound_globalbss_start,be=(uintptr_t)__encbound_globalbss_end;
    region(base,rw,ENCBOUND_REGION_TRUSTED,0);
    region(rw,re,ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_GLOBAL);
    region(re,bs,ENCBOUND_REGION_TRUSTED,0);
    region(bs,be,ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_GLOBAL);
    region(be,(uintptr_t)heap,ENCBOUND_REGION_TRUSTED,0);
    region((uintptr_t)heap,(uintptr_t)heap+sizeof(heap),ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_HEAP);
    region((uintptr_t)heap+sizeof(heap),base+0x4000000,ENCBOUND_REGION_TRUSTED,0);
    return 0;
}
int encbound_platform_get_config(encbound_platform_config_t *c) {
    *c=(encbound_platform_config_t){0};
    c->enclave_base=(uintptr_t)__executable_start;c->enclave_size=0x4000000;
    c->protected_heap_base=(uintptr_t)heap;c->protected_heap_size=sizeof(heap);
    c->regions=regions;c->region_count=count;return 0;
}
uintptr_t encbound_enclave_base(void){return (uintptr_t)__executable_start;}
uint64_t encbound_enclave_size(void){return 0x4000000;}
bool encbound_platform_get_region(uint64_t off,encbound_region_t *out) {
    for(size_t i=0;i<count;++i)if(off>=regions[i].start_offset && off-regions[i].start_offset<regions[i].size){if(out)*out=regions[i];return true;}
    return false;
}
encbound_classify_result_t encbound_platform_classify(const void *p,size_t n,encbound_region_t *out) {
    uintptr_t a=(uintptr_t)p,b=(uintptr_t)__executable_start;
    if(!n || a>UINTPTR_MAX-n)return ENCBOUND_CLASSIFY_INVALID;
    if(a+n<=b || a>=b+0x4000000)return ENCBOUND_CLASSIFY_OUTSIDE;
    encbound_region_t r;
    if(a<b || !encbound_platform_get_region(a-b,&r) || n>r.size-(a-b-r.start_offset))return ENCBOUND_CLASSIFY_INVALID;
    if(out)*out=r;return ENCBOUND_CLASSIFY_REGION;
}
int encbound_platform_random(void *p,size_t n){memset(p,0x71,n);return 0;}
_Noreturn void encbound_abort(int code){longjmp(stop,code);}
int globals_run(void);uintptr_t globals_pointer(int);int globals_read(uintptr_t);int globals_index(int);int globals_crossing(void);
int main(int argc,char **argv) {
    assert(argc==2);int code=setjmp(stop);
    if(code){printf("STOP %d\n",code);return 0;}
    if(!strcmp(argv[1],"bad-slot")) {
        *__encbound_gcaps_start=(3ull<<59)+(uintptr_t)__encbound_gcaps_start;
        int rc=encbound_runtime_init_with_key(1,2);
        assert(rc==ENCBOUND_ERR_POLICY && encbound_runtime_init()==ENCBOUND_ERR_STATE);
        puts("INIT FAILURE TERMINAL");return 0;
    }
    assert(encbound_runtime_init_with_key(0x0123456789abcdefull,0xfedcba9876543210ull)==0);
    if(!strcmp(argv[1],"session")) {
        assert(globals_run()==7);assert(encbound_runtime_init()==0);assert(globals_run()==9);
        puts("SESSION PASS");
    } else if(!strcmp(argv[1],"raw")) globals_read((uintptr_t)__encbound_globalrw_start);
    else if(!strcmp(argv[1],"table")) globals_read((uintptr_t)__encbound_gcaps_start);
    else if(!strcmp(argv[1],"invalid-entry")) encbound_global_cap((void*)((uintptr_t)__encbound_gcaps_start+1));
    else if(!strcmp(argv[1],"padding")){assert(globals_index(24)==0);puts("PADDING PASS");}
    else if(!strcmp(argv[1],"crossing")) globals_crossing();
    else if(!strcmp(argv[1],"rebase")) {
        uintptr_t a=globals_pointer(0),b=globals_pointer(1);
        assert(globals_read((a&~0xffffffffull)|(b&0xffffffffull))=='z');puts("REBASE ADMITTED");
    } else if(!strcmp(argv[1],"free")) encbound_free((void*)globals_pointer(0));
    else return 2;
    return 0;
}
