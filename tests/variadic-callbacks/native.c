/* Native modeled ELF/stack platform reused from tests/errno/native.c.
 * Executes the real allocator/checks on an actual alternate machine stack.
 * ucontext/fork/abort interception are trusted fixture code, never admitted app code.
 */
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
static unsigned char private_byte;
extern char __executable_start[];
extern char __encbound_appdata_start[], __encbound_appdata_end[];
extern char __encbound_apprelro_start[], __encbound_apprelro_end[];
extern char __encbound_apprw_start[], __encbound_apprw_end[];
extern char __encbound_appbss_start[], __encbound_appbss_end[];
extern char __encbound_globalrw_start[], __encbound_globalrw_end[];
extern char __encbound_globalbss_start[], __encbound_globalbss_end[];
extern uintptr_t __encbound_gcaps_start[], __encbound_gcaps_end[];
static unsigned char heap[1<<20] __attribute__((aligned(1<<20)));
static unsigned char app_stack[1<<20] __attribute__((aligned(1<<20)));
static encbound_region_t regions[24];
static size_t region_count;
static jmp_buf stopped;

static void region(uintptr_t lo, uintptr_t hi, unsigned policy, unsigned domain)
{
    if (lo == hi) return;
    assert(hi > lo && region_count < 24);
    regions[region_count++] = (encbound_region_t){lo-(uintptr_t)__executable_start, hi-lo, policy, domain};
}

static int compare_region(const void *a, const void *b)
{
    uint64_t left=((const encbound_region_t *)a)->start_offset;
    uint64_t right=((const encbound_region_t *)b)->start_offset;
    return (left > right) - (left < right);
}

int encbound_platform_init(void)
{
    if (region_count) return 0;
#define SPAN(name, policy, domain) region((uintptr_t)__encbound_##name##_start, (uintptr_t)__encbound_##name##_end, policy, domain)
    SPAN(appdata, ENCBOUND_REGION_COMPAT, 0);
    SPAN(apprelro, ENCBOUND_REGION_COMPAT, 0);
    SPAN(apprw, ENCBOUND_REGION_COMPAT, 0);
    SPAN(appbss, ENCBOUND_REGION_COMPAT, 0);
    SPAN(globalrw, ENCBOUND_REGION_PROTECTED, ENCBOUND_DOMAIN_GLOBAL);
    SPAN(globalbss, ENCBOUND_REGION_PROTECTED, ENCBOUND_DOMAIN_GLOBAL);
#undef SPAN
    region((uintptr_t)heap, (uintptr_t)heap+sizeof heap, ENCBOUND_REGION_PROTECTED, ENCBOUND_DOMAIN_HEAP);
    region((uintptr_t)app_stack, (uintptr_t)app_stack+sizeof app_stack, ENCBOUND_REGION_PROTECTED, ENCBOUND_DOMAIN_STACK);
    qsort(regions, region_count, sizeof regions[0], compare_region);
    size_t named=region_count;
    uint64_t cursor=0;
    for (size_t i=0; i<named; ++i) {
        assert(regions[i].start_offset >= cursor);
        region((uintptr_t)__executable_start+cursor, (uintptr_t)__executable_start+regions[i].start_offset,
               ENCBOUND_REGION_TRUSTED, 0);
        cursor=regions[i].start_offset+regions[i].size;
    }
    region((uintptr_t)__executable_start+cursor, (uintptr_t)__executable_start+0x4000000,
           ENCBOUND_REGION_TRUSTED, 0);
    qsort(regions, region_count, sizeof regions[0], compare_region);
    return 0;
}

int encbound_platform_get_config(encbound_platform_config_t *config)
{
    *config=(encbound_platform_config_t){0};
    config->enclave_base=(uintptr_t)__executable_start; config->enclave_size=0x4000000;
    config->protected_heap_base=(uintptr_t)heap; config->protected_heap_size=sizeof heap;
    config->regions=regions; config->region_count=region_count;
    return 0;
}
uintptr_t encbound_enclave_base(void) { return (uintptr_t)__executable_start; }
uint64_t encbound_enclave_size(void) { return 0x4000000; }
bool encbound_platform_get_region(uint64_t offset, encbound_region_t *out)
{
    for (size_t i=0; i<region_count; ++i)
        if (offset >= regions[i].start_offset && offset-regions[i].start_offset < regions[i].size) {
            if (out) *out=regions[i]; return true;
        }
    return false;
}
encbound_classify_result_t encbound_platform_classify(const void *p, size_t size, encbound_region_t *out)
{
    uintptr_t address=(uintptr_t)p, base=(uintptr_t)__executable_start;
    if (!size || address > UINTPTR_MAX-size) return ENCBOUND_CLASSIFY_INVALID;
    if (address+size <= base || address >= base+0x4000000) return ENCBOUND_CLASSIFY_OUTSIDE;
    encbound_region_t found;
    if (address < base || !encbound_platform_get_region(address-base, &found) ||
        size > found.size-(address-base-found.start_offset)) return ENCBOUND_CLASSIFY_INVALID;
    if (out) *out=found; return ENCBOUND_CLASSIFY_REGION;
}
bool encbound_is_outside_enclave(const void *p, size_t n)
{ return encbound_platform_classify(p, n, NULL) == ENCBOUND_CLASSIFY_OUTSIDE; }
int encbound_platform_random(void *p, size_t n) { memset(p, 0x71, n); return 0; }
int encbound_platform_get_thread_ranges(uintptr_t *stack, uint64_t *stack_size,
                                         uintptr_t *tls, uint64_t *tls_size)
{
    *stack=(uintptr_t)app_stack; *stack_size=sizeof app_stack;
    *tls=(uintptr_t)&private_byte; *tls_size=sizeof private_byte; return 0;
}
_Noreturn void encbound_abort(int code) { longjmp(stopped, code); }


long indirect_case(unsigned char *, int);
long native_indirect_case(unsigned char *, int);
static ucontext_t caller, application;
static unsigned char *argument;
static int mode;
static long result;
static void enter(void) { result=indirect_case(argument,mode); }
static void execute(void)
{
    assert(getcontext(&application)==0);
    application.uc_stack.ss_sp=app_stack; application.uc_stack.ss_size=sizeof app_stack;
    application.uc_link=&caller; makecontext(&application,enter,0);
    assert(swapcontext(&caller,&application)==0);
}
int main(void)
{
    int failure=setjmp(stopped);
    if (failure) { fprintf(stderr,"unexpected abort %d\n",failure); return 1; }
    assert(encbound_runtime_init_with_key(11,22)==0);
    unsigned char *raw;
#ifdef ENCBOUND_PROTECTED
    argument=encbound_malloc(16);
    raw=(void *)encbound_require((uintptr_t)argument,16,ENCBOUND_ACCESS_WRITE);
#else
    raw=argument=malloc(16); assert(raw);
#endif
    for (unsigned i=0;i<20;++i) {
        unsigned char oracle=11;
        assert(native_indirect_case(&oracle,0)==1023 && oracle==12);
        *raw=11; execute();
        assert(result==1023 && *raw==oracle);
    }
    unsigned controls=0;
#ifdef ENCBOUND_PROTECTED
    unsigned count=4;
#ifdef ENCBOUND_MAC27
    count=5;
#endif
    for (unsigned c=1;c<=count;++c) {
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            private_byte=0x77; argument=&private_byte; mode=(int)c;
            int error=setjmp(stopped);
            if (!error) { execute(); _exit(90); }
            assert(error==(c==4 ? ENCBOUND_ERR_RANGE : c==5 ? ENCBOUND_ERR_TAG : ENCBOUND_ERR_POLICY));
            assert(private_byte==0x77); _exit(0);
        }
        int status; assert(waitpid(child,&status,0)==child);
        assert(WIFEXITED(status) && WEXITSTATUS(status)==0); ++controls;
    }
#endif
    printf("INDIRECT VARIADIC NATIVE PASS cases=20 bits=1023 controls=%u\n",controls);
    return 0;
}
