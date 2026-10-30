/* Actual generated Intel bridges plus a separately instrumented application.
 * SDK bodies below are transport spies, not an RA protocol implementation.
 * Raw bridge allocations use the fake platform's TRUSTED region. */
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "boundary_support.h"
#include "fake_platform.h"

static void *bridge_malloc(size_t n);
static void bridge_free(void *p);
int bridge_copy_fail;
#define malloc bridge_malloc
#define free bridge_free
#include "probe_t.c"
#undef malloc
#undef free

static struct { void *p; size_t n; } slots[16];
static unsigned allocations, fail_at, live, sdk_calls, nested_checks, observations;
static int init_fail;
static sgx_status_t sdk_status = SGX_SUCCESS;
static void *transport;
static const void *last_sdk_pointer;
static ucontext_t caller, worker;
static int action;
static sgx_status_t result;
static sgx_ec256_public_t ga;
static sgx_ra_msg2_t msg2;
static sgx_target_info_t target;
static sgx_report_t report;
static sgx_quote_nonce_t nonce;
static unsigned char msg3[1024], app_bytes[16];
static ms_sgx_ra_get_ga_t ga_request;
static ms_sgx_ra_proc_msg2_trusted_t msg2_request;
static ms_sgx_ra_get_msg3_trusted_t msg3_request;
#ifndef SDK_ONLY
static ms_application_t app_request;
#endif

int __real_encbound_platform_init(void);
int __wrap_encbound_platform_init(void)
{ return init_fail ? -1 : __real_encbound_platform_init(); }

static void *bridge_malloc(size_t n)
{
    if (++allocations == fail_at) return NULL;
    assert(n <= 1024);
    for (unsigned i = 0; i < 16; ++i) if (!slots[i].p) {
        void *p = (void *)(encbound_enclave_base() + 0x300000 + i * 1024);
        slots[i].p = p; slots[i].n = n; ++live;
        memset(p, 0xca, n);
        return p;
    }
    abort();
}
static void bridge_free(void *p)
{
    if (!p) return;
    for (unsigned i = 0; i < 16; ++i) if (slots[i].p == p) {
        slots[i].p = NULL; assert(live); --live; return;
    }
    abort();
}
static void raw_buffer(const void *p, size_t n, int zero)
{
    assert(p && (uintptr_t)p >> 48 == 0);
    assert(sgx_is_within_enclave(p, n));
    unsigned found = 0;
    for (unsigned i = 0; i < 16; ++i) if (slots[i].p == p && slots[i].n == n) ++found;
    assert(found == 1);
    if (zero) for (size_t i = 0; i < n; ++i) assert(((const unsigned char *)p)[i] == 0);
#ifdef ENCBOUND_PROTECTED
    uintptr_t raw;
    assert(encbound_check((uintptr_t)p, n, ENCBOUND_ACCESS_READ, &raw) == ENCBOUND_ERR_POLICY);
#endif
    last_sdk_pointer = p;
}
int sgx_is_outside_enclave(const void *p, size_t n)
{ return p && encbound_is_outside_enclave(p, n); }
int sgx_is_within_enclave(const void *p, size_t n)
{
    uintptr_t a = (uintptr_t)p, b = encbound_enclave_base();
    return a >= b && a - b < encbound_enclave_size() && n <= encbound_enclave_size() - (a - b);
}
static void nested(void)
{
#ifdef ENCBOUND_PROTECTED
    /* Copy-failure injection targets the outer call's transport sequence. */
    int saved_copy_failure = bridge_copy_fail;
    bridge_copy_fail = 0;
    /* Marshaling requests live on the modeled host, outside the fake SDK
     * stack. An enclave-local request would fail Intel's pointer check first. */
    static ms_sgx_ra_get_ga_t g;
    assert(sgx_sgx_ra_get_ga(&g) == SGX_ERROR_ECALL_NOT_ALLOWED); ++nested_checks;
#ifndef SDK_ONLY
    static ms_application_t a;
    assert(sgx_application(&a) == SGX_ERROR_ECALL_NOT_ALLOWED); ++nested_checks;
#endif
    /* Refusal must not release the still-active outer call. */
    assert(encbound_boundary_admit() != 0); ++nested_checks;
    bridge_copy_fail = saved_copy_failure;
#endif
}
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t *p)
{
    ++sdk_calls; assert(context == 7);
    if (p) { raw_buffer(p, sizeof(*p), 1); memset(p, 0x61, sizeof(*p)); }
    nested();
    return sdk_status;
}
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t *m,
        const sgx_target_info_t *t, sgx_report_t *r, sgx_quote_nonce_t *q)
{
    ++sdk_calls; assert(context == 7);
    raw_buffer(m, sizeof(*m), 0); assert(!memcmp(m, &msg2, sizeof(*m)));
    raw_buffer(t, sizeof(*t), 0); assert(!memcmp(t, &target, sizeof(*t)));
    raw_buffer(r, sizeof(*r), 1); raw_buffer(q, sizeof(*q), 1);
    memset(r, 0x72, sizeof(*r)); memset(q, 0x73, sizeof(*q));
    nested();
    return sdk_status;
}
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size,
        sgx_report_t *r, sgx_ra_msg3_t *m, uint32_t n)
{
    ++sdk_calls; assert(context == 7 && quote_size == 19 && n == sizeof(msg3));
    raw_buffer(r, sizeof(*r), 0); assert(!memcmp(r, &report, sizeof(*r)));
    assert(m == msg3_request.ms_p_msg3); /* exact [user_check] bits */
    nested();
    /* This spy models the SDK-owned outside check, not bridge validation. */
    if (!sgx_is_outside_enclave(m, n)) return SGX_ERROR_INVALID_PARAMETER;
    memset(m, 0x83, n);
    return sdk_status;
}
void *sgx_ocalloc(size_t n) { assert(!transport); return transport = malloc(n); }
void sgx_ocfree(void) { free(transport); transport = NULL; }
sgx_status_t sgx_ocall(unsigned index, void *data)
{
#ifndef SDK_ONLY
    assert(index == 0); ++observations;
    const unsigned char *p = ((ms_observe_t *)data)->ms_value;
#ifdef ENCBOUND_PROTECTED
    assert((uintptr_t)p >> 59 > 0 && (uintptr_t)p >> 59 < 31);
    const unsigned char *raw = (const void *)encbound_require((uintptr_t)p, 16, ENCBOUND_ACCESS_READ);
#else
    const unsigned char *raw = p;
#endif
    for (size_t i = 0; i < 16; ++i) assert(raw[i] == i + 1);
    nested();
    return SGX_SUCCESS;
#else
    (void)index; (void)data; abort();
#endif
}
static void entry(void)
{
    if (action == 0) result = sgx_sgx_ra_get_ga(&ga_request);
    else if (action == 1) result = sgx_sgx_ra_proc_msg2_trusted(&msg2_request);
    else if (action == 2) result = sgx_sgx_ra_get_msg3_trusted(&msg3_request);
#ifndef SDK_ONLY
    else result = sgx_application(&app_request);
#else
    else abort();
#endif
}
static sgx_status_t call(int next_action)
{
    action = next_action;
    getcontext(&worker);
    worker.uc_link = &caller;
    worker.uc_stack.ss_sp = (void *)(encbound_enclave_base() + 0x100000);
    worker.uc_stack.ss_size = 0x100000;
    makecontext(&worker, entry, 0);
    assert(swapcontext(&caller, &worker) == 0);
    assert(live == 0 && !transport);
#ifdef ENCBOUND_PROTECTED
    assert(encbound_boundary_admit() == 0); encbound_boundary_release();
#endif
    return result;
}
static void child_failure(int terminal)
{
#ifdef ENCBOUND_PROTECTED
    pid_t p = fork(); assert(p >= 0);
    if (!p) {
        if (terminal) encbound_boundary_fail(); else init_fail = 1;
        unsigned before = sdk_calls;
        entry();
        assert(result == (terminal ? SGX_ERROR_ECALL_NOT_ALLOWED : SGX_ERROR_UNEXPECTED));
        init_fail = 0; entry();
        assert(result == SGX_ERROR_ECALL_NOT_ALLOWED && sdk_calls == before);
        _exit(0);
    }
    int status; assert(waitpid(p, &status, 0) == p && WIFEXITED(status) && WEXITSTATUS(status) == 0);
#else
    (void)terminal;
#endif
}
int main(void)
{
    ga_request = (ms_sgx_ra_get_ga_t){.ms_context = 7, .ms_g_a = &ga};
    msg2_request = (ms_sgx_ra_proc_msg2_trusted_t){.ms_context = 7, .ms_p_msg2 = &msg2,
        .ms_p_qe_target = &target, .ms_p_report = &report, .ms_p_nonce = &nonce};
    msg3_request = (ms_sgx_ra_get_msg3_trusted_t){.ms_context = 7, .ms_quote_size = 19,
        .ms_qe_report = &report, .ms_p_msg3 = (void *)msg3, .ms_msg3_size = sizeof(msg3)};
    /* Initialization failure is tested before this process initializes. */
    action = 0; child_failure(0);
    memset(&msg2, 0x42, sizeof(msg2)); memset(&target, 0x53, sizeof(target));
    assert(call(0) == SGX_SUCCESS && ga_request.ms_retval == SGX_SUCCESS);
    for (size_t i = 0; i < sizeof(ga); ++i) assert(((unsigned char *)&ga)[i] == 0x61);
    assert(call(1) == SGX_SUCCESS && msg2_request.ms_retval == SGX_SUCCESS);
    for (size_t i = 0; i < sizeof(report); ++i) assert(((unsigned char *)&report)[i] == 0x72);
    for (size_t i = 0; i < sizeof(nonce); ++i) assert(((unsigned char *)&nonce)[i] == 0x73);
    assert(call(2) == SGX_SUCCESS && msg3_request.ms_retval == SGX_SUCCESS);
    for (size_t i = 0; i < sizeof(msg3); ++i) assert(msg3[i] == 0x83);
    msg3_request.ms_p_msg3 = (void *)(encbound_enclave_base() + 0x300000);
    assert(call(2) == SGX_SUCCESS && msg3_request.ms_retval == SGX_ERROR_INVALID_PARAMETER);
    msg3_request.ms_p_msg3 = (void *)msg3;
    sdk_status = SGX_ERROR_INVALID_STATE;
    assert(call(1) == SGX_SUCCESS && msg2_request.ms_retval == sdk_status);
    sdk_status = SGX_SUCCESS;
    for (unsigned i = 1; i <= 4; ++i) {
        allocations = 0; fail_at = i; unsigned before = sdk_calls;
        assert(call(1) == SGX_ERROR_OUT_OF_MEMORY && sdk_calls == before);
        fail_at = 0; assert(call(0) == SGX_SUCCESS);
    }
    for (int i = 1; i <= 6; ++i) {
        bridge_copy_fail = i;
        assert(call(1) == SGX_ERROR_UNEXPECTED);
        bridge_copy_fail = 0; assert(call(0) == SGX_SUCCESS);
    }
    /* Copied pointers keep Intel's outside check; user_check stays SDK-owned. */
    ga_request.ms_g_a = (void *)(encbound_enclave_base() + 0x300000);
    unsigned before = sdk_calls;
    assert(call(0) == SGX_ERROR_INVALID_PARAMETER && sdk_calls == before);
    ga_request.ms_g_a = NULL;
    assert(call(0) == SGX_SUCCESS);
    ga_request.ms_g_a = &ga;
#ifndef SDK_ONLY
    for (size_t i = 0; i < sizeof(app_bytes); ++i) app_bytes[i] = i;
    app_request = (ms_application_t){.ms_p = app_bytes, .ms_n = sizeof(app_bytes)};
    assert(call(3) == SGX_SUCCESS && app_request.ms_retval == 41 && observations == 1);
    for (size_t i = 0; i < sizeof(app_bytes); ++i) assert(app_bytes[i] == i + 1);
#endif
#ifdef ENCBOUND_PROTECTED
    uintptr_t raw;
    assert(encbound_check((uintptr_t)last_sdk_pointer, 1, ENCBOUND_ACCESS_READ, &raw) == ENCBOUND_ERR_POLICY);
    action = 0; child_failure(1);
    assert(nested_checks > 0);
#endif
    printf("SDK ECALL NATIVE PASS calls=%u nested_refusals=%u allocation_failures=4 copy_failures=6 app_observations=%u\n",
        sdk_calls, nested_checks, observations);
    return 0;
}
