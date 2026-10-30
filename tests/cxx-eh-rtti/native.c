/* Native test layout over the actual linked image. Real checks/allocation and
 * ABI adaptation; system DWARF unwinder. No SGX isolation/backend claim.
 * calloc wrapping confines real private EH headers inside this test image. */
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <sys/wait.h>
#include <unistd.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "cxx_eh/runtime.h"
extern char __executable_start[];
#define RANGE(n) extern char __encbound_##n##_start[],__encbound_##n##_end[]
RANGE(appdata);RANGE(apprelro);RANGE(globalrw);RANGE(globalbss);
static unsigned char heap[1<<22] __attribute__((aligned(1<<22)));
static unsigned char stack[1<<20] __attribute__((aligned(1<<20)));
static unsigned char headers[64][512] __attribute__((aligned(16)));
static unsigned used[64],private_live;
static void *last_header;
static encbound_region_t regions[20];static size_t count;
static jmp_buf stop;
static int abort_ready;
static ucontext_t caller,application;
static int action,result,read_private;
static uintptr_t private_address;
extern void (*__start_encbound_native_init[])(void),(*__stop_encbound_native_init[])(void);
static void (*destructors[16])(void *);static void *arguments[16];static unsigned registrations;
int __wrap___cxa_atexit(void (*f)(void*),void *p,void *dso) {
    (void)dso;assert(registrations<16);destructors[registrations]=f;arguments[registrations++]=p;return 0;
}
static void interval(uintptr_t lo,uintptr_t hi,unsigned policy,unsigned domain) {
    if(lo==hi)return;assert(hi>lo);
    regions[count++]=(encbound_region_t){lo-(uintptr_t)__executable_start,hi-lo,policy,domain};
}
static int compare(const void *a,const void *b) {
    uint64_t x=((const encbound_region_t*)a)->start_offset,y=((const encbound_region_t*)b)->start_offset;
    return (x>y)-(x<y);
}
int encbound_platform_init(void) {
    if(count)return 0;
    interval((uintptr_t)__encbound_appdata_start,(uintptr_t)__encbound_appdata_end,ENCBOUND_REGION_COMPAT,0);
    interval((uintptr_t)__encbound_apprelro_start,(uintptr_t)__encbound_apprelro_end,ENCBOUND_REGION_COMPAT,0);
    interval((uintptr_t)__encbound_globalrw_start,(uintptr_t)__encbound_globalrw_end,ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_GLOBAL);
    interval((uintptr_t)__encbound_globalbss_start,(uintptr_t)__encbound_globalbss_end,ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_GLOBAL);
    interval((uintptr_t)heap,(uintptr_t)heap+sizeof(heap),ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_HEAP);
    interval((uintptr_t)stack,(uintptr_t)stack+sizeof(stack),ENCBOUND_REGION_PROTECTED,ENCBOUND_DOMAIN_STACK);
    qsort(regions,count,sizeof(*regions),compare);
    encbound_region_t copy[8];size_t n=count;memcpy(copy,regions,n*sizeof(*copy));count=0;
    uintptr_t base=(uintptr_t)__executable_start,at=base;
    for(size_t i=0;i<n;++i){uintptr_t lo=base+copy[i].start_offset;assert(lo>=at);interval(at,lo,ENCBOUND_REGION_TRUSTED,0);regions[count++]=copy[i];at=lo+copy[i].size;}
    assert(at<=base+0x4000000);interval(at,base+0x4000000,ENCBOUND_REGION_TRUSTED,0);return 0;
}
int encbound_platform_get_config(encbound_platform_config_t *c) {
    *c=(encbound_platform_config_t){0};c->enclave_base=(uintptr_t)__executable_start;c->enclave_size=0x4000000;
    c->protected_heap_base=(uintptr_t)heap;c->protected_heap_size=sizeof(heap);c->regions=regions;c->region_count=count;return 0;
}
uintptr_t encbound_enclave_base(void){return (uintptr_t)__executable_start;}
uint64_t encbound_enclave_size(void){return 0x4000000;}
bool encbound_platform_get_region(uint64_t offset,encbound_region_t *out) {
    for(size_t i=0;i<count;++i)if(offset>=regions[i].start_offset && offset-regions[i].start_offset<regions[i].size){if(out)*out=regions[i];return true;}return false;
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
_Noreturn void encbound_abort(int code){if(!abort_ready)_exit(80+code);longjmp(stop,code);}
/* Observe the terminal C++ service in this native-only harness. */
_Noreturn void __wrap_abort(void){encbound_abort(ENCBOUND_ERR_STATE);}
void *__real_calloc(size_t,size_t);void __real_free(void *);
void *__wrap_calloc(size_t n,size_t size) {
    assert(n && size<=512/n);
    for(unsigned i=0;i<64;++i)if(!used[i]){used[i]=1;++private_live;last_header=headers[i];memset(headers[i],0,512);return headers[i];}
    return NULL;
}
void __wrap_free(void *p) {
    for(unsigned i=0;i<64;++i)if(p==headers[i]){assert(used[i]);used[i]=0;--private_live;return;}
    __real_free(p);
}
extern int __encbound_eh_entry_exercise(int),private_read(uintptr_t),private_cast(uintptr_t);
extern void *encbound_eh_allocate_exception(size_t);
extern void encbound_eh_free_exception(void *),encbound_eh_boundary_clean(void);
static void enter(void){
    if(action==-1){for(void (**f)(void)=__start_encbound_native_init;f<__stop_encbound_native_init;++f)(*f)();return;}
    if(action==-2){while(registrations){--registrations;destructors[registrations](arguments[registrations]);}return;}
    result=read_private==2 ? private_cast(private_address) : read_private ? private_read(private_address) : __encbound_eh_entry_exercise(action);
}
static void execute(void) {
    assert(getcontext(&application)==0);application.uc_stack.ss_sp=stack;application.uc_stack.ss_size=sizeof(stack);application.uc_link=&caller;
    makecontext(&application,enter,0);assert(swapcontext(&caller,&application)==0);
}
void encbound_early_bootstrap(void){if(encbound_runtime_init_with_key(11,22)!=0)_exit(80);}
int main(void) {
    abort_ready=1;
    int code=setjmp(stop);if(code){fprintf(stderr,"unexpected STOP %d action %d\n",code,action);return 1;}
    assert(encbound_runtime_init_with_key(11,22)==0);
    action=-1;execute();assert(registrations==1);encbound_eh_boundary_clean();
    int expected[]={12,5,-9,21,1,31,32,47,18,1,19,13,1,1,1,12,14,37,19,53,1,19,55,38,1,39,63,1};
    for(int repeat=0;repeat<9;++repeat)for(action=0;action<(int)(sizeof(expected)/sizeof(expected[0]));++action){execute();assert(result==(repeat && action==2 ? 21 : expected[action]));assert(private_live==0);}
    action=130;execute();assert(result==1 && private_live==0);
    encbound_eh_boundary_clean();struct encbound_eh_stats_t stats=encbound_eh_stats();assert(!stats.live && !stats.bytes && !stats.rounded && stats.peak>=2);
    void *entire=encbound_malloc(sizeof(heap));assert(entire);encbound_free(entire); // full buddy coalescence after recovery
    unsigned controls=0;
    for(int index=0;index<14;++index) {
        int test=index<11 ? 100+index : 120+index-11;
#ifndef ENCBOUND_MAC27
        if(test==101 || test==121)continue;
#endif
        pid_t child=fork();assert(child>=0);
        if(!child) {
            action=test;read_private=0;
            if(test>=106 && test<=108){(void)encbound_eh_allocate_exception(32);read_private=1;private_address=(uintptr_t)last_header+(test==107 ? stats.unwind_offset : 0);if(test==108)private_address=(uintptr_t)&application;}
            if(test==122){(void)encbound_eh_allocate_exception(32);read_private=2;private_address=(uintptr_t)last_header;}
            if(test==109){assert(encbound_malloc(sizeof(heap)));action=0;}
            if(test==110){for(unsigned i=0;i<64;++i)assert(encbound_eh_allocate_exception(32));action=0;}
            unsigned char before[sizeof(headers)];memcpy(before,headers,sizeof(headers));
            int failure=setjmp(stop);
            if(!failure){execute();_exit(91);}
            int want=test==120 ? ENCBOUND_ERR_RANGE : test==121 ? ENCBOUND_ERR_TAG : test==122 ? ENCBOUND_ERR_POLICY : test>=109 ? ENCBOUND_ERR_DEPLETED : test==100 || test==105 ? ENCBOUND_ERR_RANGE : test==101 ? ENCBOUND_ERR_TAG : test==102 || test>=106 ? ENCBOUND_ERR_POLICY : ENCBOUND_ERR_STATE;
            if(failure!=want){fprintf(stderr,"test %d code %d wanted %d\n",test,failure,want);_exit(92);}
            if(test>=106 && test<=108 && memcmp(before,headers,sizeof(headers)))_exit(93);
            if(test==109 && private_live)_exit(94);
            _exit(0);
        }
        int status;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status) && WEXITSTATUS(status)==0);++controls;
    }
    action=-2;execute();assert(!registrations);encbound_eh_boundary_clean();
    printf("CXX EH NATIVE PASS: %zu calls, %u attributed controls, peak headers=%zu requested=%zu rounded=%zu header_size=%zu allocations=%zu; complete heap reclaimed\n",9*sizeof(expected)/sizeof(expected[0])+1,controls,stats.peak,stats.peak_bytes,stats.peak_rounded,stats.header_size,stats.allocations);
}
