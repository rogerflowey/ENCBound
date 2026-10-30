/* Native real-runtime execution over the linked image and a modeled SDK stack.
 * Platform/layout pattern reused from protected_globals_native.c. No SGX claim. */
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <errno.h>
#include <limits.h>
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

static int sdk_errno;
#undef errno
#define errno sdk_errno
int bridge_copy_fail;
#include "probe_t.c"

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
    *tls=(uintptr_t)&sdk_errno; *tls_size=sizeof sdk_errno; return 0;
}
_Noreturn void encbound_abort(int code) { longjmp(stopped, code); }

uintptr_t errno_sdk_address(void) { sdk_errno=0x5a17; return (uintptr_t)&sdk_errno; }
int errno_sdk_read(void) { return sdk_errno; }
int sgx_is_outside_enclave(const void *p, size_t n) { return p && encbound_is_outside_enclave(p, n); }
int sgx_is_within_enclave(const void *p, size_t n)
{
    uintptr_t a=(uintptr_t)p, b=encbound_enclave_base();
    return a >= b && a-b < encbound_enclave_size() && n <= encbound_enclave_size()-(a-b);
}

static void *transport;
static int allocation_fail, fail_transport, fail_after_host, mutate_errno;
static unsigned host_calls, errno_reads;
static int *errno_source;
sgx_status_t errno_host_dispatch(unsigned, void *);
void errno_host_prepare(int);

void *sgx_ocalloc(size_t n)
{
    assert(!transport);
    return allocation_fail ? NULL : (transport=malloc(n));
}
void sgx_ocfree(void) { free(transport); transport=NULL; errno_source=NULL; }
sgx_status_t sgx_ocall(unsigned index, void *data)
{
    if (fail_transport == 1) return SGX_ERROR_UNEXPECTED;
    ++host_calls;
    sgx_status_t status=errno_host_dispatch(index, data);
    if (fail_transport == 2) return SGX_ERROR_UNEXPECTED;
    errno_source=index==0 ? &((ms_errno_exchange_t *)data)->ocall_errno :
                 index==1 ? &((ms_errno_void_t *)data)->ocall_errno :
                 index==2 ? &((ms_errno_naked_t *)data)->ocall_errno : NULL;
    bridge_copy_fail=fail_after_host;
    return status;
}
void errno_test_after_copy(const void *source, size_t size)
{
    if (source == errno_source && size == sizeof(int)) {
        ++errno_reads;
        if (mutate_errno) *errno_source=0x6789;
    }
}

static ucontext_t caller, application;
static unsigned call_kind;
static void *call_data;
static sgx_status_t call_status;
static void enter(void)
{
    switch (call_kind) {
    case 0: call_status=sgx_errno_case(call_data); break;
    case 1: call_status=sgx_errno_read(call_data); break;
    case 2: call_status=sgx_errno_write(call_data); break;
    case 3: call_status=sgx_errno_pointer(call_data); break;
    case 4: call_status=sgx_errno_access(call_data); break;
    default: abort();
    }
}
static void execute(unsigned kind, void *data)
{
    call_kind=kind; call_data=data;
    assert(getcontext(&application) == 0);
    application.uc_stack.ss_sp=app_stack; application.uc_stack.ss_size=sizeof app_stack;
    application.uc_link=&caller; makecontext(&application, enter, 0);
    assert(swapcontext(&caller, &application) == 0);
    assert(call_status == SGX_SUCCESS && !transport);
}
static int read_app(void)
{ ms_errno_read_t request={0}; execute(1, &request); return request.ms_retval; }

int main(void)
{
    int code=setjmp(stopped);
    if (code) { fprintf(stderr, "unexpected abort %d\n", code); return 1; }
    assert(encbound_runtime_init_with_key(0x123456789abcdefULL, 0xfedcba9876543210ULL) == 0);
    assert(read_app() == 0);
    int observed[8], previous=0; unsigned cases=0, controls=0;
    const int values[]={0, ENOENT, EACCES, INT_MAX, -71, INT_MIN};
    for (unsigned repetition=0; repetition<2; ++repetition)
    for (unsigned i=0; i<sizeof values/sizeof values[0]; ++i)
    for (int action=0; action<5; ++action) {
        int value=values[i], initial=200+(int)cases, result=cases%2 ? -1 : 97;
        errno_host_prepare(317); sdk_errno=719;
        ms_errno_case_t request={.ms_action=action, .ms_initial=initial,
            .ms_value=value, .ms_result=result, .ms_observed=observed};
        execute(0, &request);
        int expected=action==2 ? initial : action==3 ? 317 :
                     action==4 ? value : value==INT_MIN ? 317 : value;
        assert(request.ms_retval == expected && observed[0] == previous && observed[1] == initial);
        assert(observed[2] == SGX_SUCCESS && observed[6] == expected && observed[7] == expected);
        assert(observed[3] == (action==0 || action==2 ? result : -900));
        assert(observed[4] == (action==0 ? 33 : 11) && observed[5] == (action==0 ? 44 : 22));
        assert(sdk_errno == (action==2 || action==4 ? 719 : expected));
        assert(read_app() == expected); previous=expected; ++cases;
    }
    ms_errno_write_t write={.ms_value=83}; execute(2, &write);
    assert(write.ms_retval == 83 && read_app() == 83);
    for (int failure=1; failure<=2; ++failure) {
        fail_transport=failure; sdk_errno=719;
        ms_errno_case_t request={.ms_initial=89, .ms_value=13, .ms_result=-1, .ms_observed=observed};
        execute(0, &request);
        assert(request.ms_retval == 89 && observed[2] == SGX_ERROR_UNEXPECTED && sdk_errno == 719);
        assert(observed[3] == -900 && observed[4] == 11 && observed[6] == 89 && observed[7] == 89);
        fail_transport=0;
    }
    allocation_fail=1;
    ms_errno_case_t request={.ms_initial=91, .ms_value=13, .ms_result=-1, .ms_observed=observed};
    unsigned calls=host_calls; execute(0, &request); allocation_fail=0;
    assert(request.ms_retval == 91 && observed[2] == SGX_ERROR_UNEXPECTED && host_calls == calls);
    for (int failure=1; failure<=3; ++failure) {
        fail_after_host=failure; sdk_errno=719;
        request.ms_initial=93; execute(0, &request); fail_after_host=0;
        assert(!bridge_copy_fail && request.ms_retval == 93 && observed[2] == SGX_ERROR_UNEXPECTED);
        assert(observed[3] == (failure==1 ? -900 : -1));
        assert(observed[4] == (failure<3 ? 11 : 33) && observed[5] == (failure<3 ? 22 : 44));
        assert(sdk_errno == 719 && observed[6] == 93 && observed[7] == 93);
    }
    for (int action=1; action<=3; action+=2) {
        fail_after_host=1; request.ms_action=action; request.ms_initial=95;
        execute(0, &request); fail_after_host=0;
        assert(request.ms_retval == 95 && observed[2] == SGX_ERROR_UNEXPECTED && observed[6] == 95);
    }
    unsigned reads=errno_reads; mutate_errno=1;
    request.ms_action=0; request.ms_value=8193;
    execute(0, &request); mutate_errno=0;
    assert(request.ms_retval == 8193 && observed[6] == 8193 && sdk_errno == 8193 && errno_reads == reads+1);
    ms_errno_pointer_t pointer={0}; execute(3, &pointer);
    uintptr_t cell=pointer.ms_retval;
    assert(cell != (uintptr_t)&sdk_errno);
#ifdef ENCBOUND_PROTECTED
    int *raw=(void *)encbound_require(cell, sizeof(int), ENCBOUND_ACCESS_READ);
    encbound_region_t owned;
    assert(encbound_platform_classify(raw, sizeof *raw, &owned) == ENCBOUND_CLASSIFY_REGION &&
           owned.policy == ENCBOUND_REGION_PROTECTED && owned.domain == ENCBOUND_DOMAIN_GLOBAL);
    for (unsigned c=0; c<6; ++c) {
#ifndef ENCBOUND_MAC27
        if (c==3) continue;
#endif
        pid_t child=fork(); assert(child >= 0);
        if (!child) {
            int before_sdk=sdk_errno, before_cell=*raw;
            int failure=setjmp(stopped);
            if (!failure) {
                uintptr_t target=c<2 ? (uintptr_t)&sdk_errno : c==2 ? (uintptr_t)raw :
                    c==3 ? cell^(UINT64_C(1)<<32) : c==4 ? cell+3 : (uintptr_t)__encbound_gcaps_start;
                ms_errno_access_t access={.ms_pointer=(int *)target, .ms_write=(c==1)};
                execute(4, &access); _exit(90);
            }
            assert(failure == (c==3 ? ENCBOUND_ERR_TAG : c==4 ? ENCBOUND_ERR_RANGE : ENCBOUND_ERR_POLICY));
            assert(sdk_errno == before_sdk && *raw == before_cell); _exit(0);
        }
        int status; assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0); ++controls;
    }
#else
    ms_errno_access_t access={.ms_pointer=&sdk_errno, .ms_write=0};
    execute(4, &access); assert(access.ms_retval == sdk_errno);
    access.ms_write=1; execute(4, &access); assert(sdk_errno == 0x1357);
#endif
    printf("ERRNO NATIVE PASS cases=%u copy_failures=5 transport_failures=2 allocation_failures=1 controls=%u\n", cases, controls);
    return 0;
}
