/* Tests actual Intel-emitted bridge C with native SDK transport/app stubs.
 * Each test executes in its own process; no SGX isolation claim. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "boundary_support.h"
#include "fake_platform.h"

int bridge_copy_fail;
#include "enclave_t.c"

static int app_calls, app_status = 73, seen_null, nested, alloc_count, live_count;
static int fail_at, tracking, host_calls, host_fail, ocalloc_fail, init_fail;
static size_t seen_size;
static const void *rejected_host;
static void *ocbuf;
static char observed[8192];
static void *persistent;

void *__real_malloc(size_t);
void __real_free(void *);
void *__real_encbound_malloc(size_t);
void __real_encbound_free(void *);
int __real_encbound_platform_init(void);
int __wrap_encbound_platform_init(void)
{ return init_fail ? -1 : __real_encbound_platform_init(); }

void *__wrap_encbound_malloc(size_t n)
{
    if (tracking && ++alloc_count == fail_at) return NULL;
    void *p = __real_encbound_malloc(n);
    if (tracking && p) ++live_count;
    return p;
}
void __wrap_encbound_free(void *p)
{ if (tracking && p) --live_count; __real_encbound_free(p); }
void *__wrap_malloc(size_t n)
{
#ifndef ENCBOUND_PROTECTED
    if (tracking && ++alloc_count == fail_at) return NULL;
#endif
    void *p = __real_malloc(n);
#ifndef ENCBOUND_PROTECTED
    if (tracking && p) ++live_count;
#endif
    return p;
}
void __wrap_free(void *p)
{
#ifndef ENCBOUND_PROTECTED
    if (tracking && p) --live_count;
#endif
    __real_free(p);
}
static void *app_raw(const void *p, size_t n)
{
#ifdef ENCBOUND_PROTECTED
    return p ? (void *)encbound_require((uintptr_t)p, n, ENCBOUND_ACCESS_READWRITE) : NULL;
#else
    (void)n; return (void *)p;
#endif
}
static void *app_alloc(size_t n)
{
#ifdef ENCBOUND_PROTECTED
    return encbound_malloc(n);
#else
    return malloc(n);
#endif
}
int sgx_is_outside_enclave(const void *p, size_t n)
{
    uintptr_t a = (uintptr_t)p, b = encbound_enclave_base();
    if (p == rejected_host || (n && a > UINTPTR_MAX - (n - 1))) return 0;
    return a < b || a >= b + encbound_enclave_size();
}
int sgx_is_within_enclave(const void *p, size_t n)
{
#ifdef ENCBOUND_PROTECTED
    uintptr_t a = (uintptr_t)p, b = encbound_enclave_base();
    return a >= b && a - b < encbound_enclave_size() &&
           n <= encbound_enclave_size() - (a - b);
#else
    /* Native malloc substitutes for SDK heap in stock bridge fixture. */
    return p != NULL && (uintptr_t)p < (1ull << 47) && n < (1ull << 30);
#endif
}
void *sgx_ocalloc(size_t n)
{ assert(!ocbuf); return ocalloc_fail ? NULL : (ocbuf = __real_malloc(n)); }
void sgx_ocfree(void)
{ __real_free(ocbuf); ocbuf = NULL; }
sgx_status_t sgx_ocall(unsigned index, void *p)
{
    ++host_calls;
    if (host_fail) return SGX_ERROR_UNEXPECTED;
    if (index == 0) {
        const char *s = ((ms_ocall_debug_print_t *)p)->ms_str;
        seen_null = s == NULL;
        if (s) strcpy(observed, s);
    } else if (index == 1) {
        ms_ocall_save_wallet_t *m = p;
        m->ms_retval = 91; seen_size = m->ms_sealed_size;
        seen_null = m->ms_sealed_data == NULL;
        if (m->ms_sealed_data && seen_size) memcpy(observed, m->ms_sealed_data, seen_size);
    } else if (index == 2) {
        ms_ocall_load_wallet_t *m = p;
        m->ms_retval = 92;
        if (m->ms_sealed_data && m->ms_sealed_size)
            memset(m->ms_sealed_data, 0x5a, m->ms_sealed_size);
    } else if (index == 3) ((ms_ocall_is_wallet_t *)p)->ms_retval = 93;
    else assert(index >= 4); /* SDK-only raw services still have stock proxies. */
    return SGX_SUCCESS;
}

int ecall_create_wallet(const char *p)
{
    ++app_calls; seen_null = !p;
    if (p) {
#ifdef ENCBOUND_PROTECTED
        size_t n = encbound_strlen(p);
#else
        size_t n = strlen(p);
#endif
        assert(n < sizeof(observed)); memcpy(observed, app_raw(p, n + 1), n + 1);
    }
#ifdef ENCBOUND_PROTECTED
    if (nested) {
        ms_ecall_remove_item_t m = { .ms_master_password = NULL, .ms_master_password_len = 0 };
        assert(sgx_ecall_remove_item(&m) == SGX_ERROR_ECALL_NOT_ALLOWED);
    }
#endif
    return app_status;
}
int ecall_show_wallet(const char *p, wallet_t *out, size_t n)
{
    (void)p; ++app_calls; seen_size = n; seen_null = !out;
    if (out && n) {
        unsigned char *raw = app_raw(out, n);
        for (size_t i = 0; i < n; ++i) assert(raw[i] == 0);
        memset(raw, 0x42, n);
    }
    return app_status; /* Stock semantics export output even on app error. */
}
int ecall_change_master_password(const char *a, const char *b)
{
    ++app_calls;
    assert(!memcmp(app_raw(a, 4), "old", 4));
    assert(!memcmp(app_raw(b, 4), "new", 4));
    return app_status;
}
int ecall_add_item(const char *p, const item_t *item, size_t n)
{ (void)p; ++app_calls; seen_size = n; seen_null = !item; return app_status; }
int ecall_remove_item(const char *p, int index)
{ (void)p; ++app_calls; assert(index == -17); return app_status; }

static sgx_status_t create(const char *p, size_t n)
{
    ms_ecall_create_wallet_t m = { .ms_master_password=p, .ms_master_password_len=n };
    sgx_status_t st = sgx_ecall_create_wallet(&m);
    if (st == SGX_SUCCESS) assert(m.ms_retval == app_status);
    return st;
}
static void inputs(void)
{
    assert(create(NULL, 0) == SGX_SUCCESS && seen_null);
    assert(create(NULL, 100) == SGX_SUCCESS && seen_null);
    assert(create("x", 0) == SGX_SUCCESS && seen_null);
    assert(create("", 1) == SGX_SUCCESS && !seen_null);
    char big[5000]; memset(big, 'p', sizeof(big)); big[4999] = 0;
    tracking = 1; alloc_count = 0;
    assert(create(big, sizeof(big)) == SGX_SUCCESS && strlen(observed) == 4999);
    assert(alloc_count == 1 && live_count == 0); tracking = 0;
    char malformed[] = {'a', 0, 'b', 0};
    int previous = app_calls;
    assert(create(malformed, sizeof(malformed)) == SGX_ERROR_UNEXPECTED);
    assert(app_calls == previous);
    assert(create("ok", 3) == SGX_SUCCESS); /* gate recovered */
    char unterminated[] = {'a', 'b', 'c'};
    assert(create(unterminated, sizeof(unterminated)) == SGX_SUCCESS);
    assert(!strcmp(observed, "ab")); /* Intel terminates the final copied byte. */
    rejected_host = big;
    assert(create(big, sizeof(big)) == SGX_ERROR_INVALID_PARAMETER);
    rejected_host = NULL;
    assert(create("ok", 3) == SGX_SUCCESS);
    ms_ecall_remove_item_t m = { .ms_index=-17 };
    assert(sgx_ecall_remove_item(&m) == SGX_SUCCESS);
}
static void outputs(void)
{
    unsigned char out[sizeof(wallet_t) + 1];
    for (size_t n = 0; n <= sizeof(out); n = n == 0 ? 16 : n == 16 ? sizeof(out) : sizeof(out)+1) {
        ms_ecall_show_wallet_t m = {.ms_wallet=(wallet_t *)out, .ms_wallet_size=n};
        memset(out, 0xa5, sizeof(out)); tracking = 1; alloc_count = 0;
        assert(sgx_ecall_show_wallet(&m) == SGX_SUCCESS && m.ms_retval == app_status);
        assert(seen_size == n && seen_null == (n == 0));
        assert(alloc_count == (n != 0) && live_count == 0); tracking = 0;
        for (size_t i = 0; i < n; ++i) assert(out[i] == 0x42);
        if (n < sizeof(out)) assert(out[n] == 0xa5);
    }
    ms_ecall_show_wallet_t nullout = {.ms_wallet_size=16};
    assert(sgx_ecall_show_wallet(&nullout) == SGX_SUCCESS && seen_null);
    unsigned char item[sizeof(item_t)+1] = {0};
    for (size_t n = 0; n <= sizeof(item); n = n == 0 ? 1 : n == 1 ? sizeof(item) : sizeof(item)+1) {
        ms_ecall_add_item_t m = {.ms_item=(item_t *)item, .ms_item_size=n};
        assert(sgx_ecall_add_item(&m) == SGX_SUCCESS && seen_size == n);
    }
}
static void cleanup(void)
{
    for (int i = 1; i <= 2; ++i) {
        ms_ecall_change_master_password_t m = {.ms_old_password="old", .ms_old_password_len=4,
            .ms_new_password="new", .ms_new_password_len=4};
        tracking = 1; alloc_count = 0; fail_at = i;
        int previous = app_calls;
        assert(sgx_ecall_change_master_password(&m) == SGX_ERROR_OUT_OF_MEMORY);
        assert(app_calls == previous && live_count == 0);
        fail_at = 0; alloc_count = 0;
        assert(sgx_ecall_change_master_password(&m) == SGX_SUCCESS);
        assert(alloc_count == 2 && live_count == 0); tracking = 0;
    }
    for (int i = 1; i <= 3; ++i) {
        bridge_copy_fail = i; tracking = 1; alloc_count = 0;
        assert(create("ok", 3) == SGX_ERROR_UNEXPECTED);
        assert(live_count == 0); tracking = 0; bridge_copy_fail = 0;
        assert(create("ok", 3) == SGX_SUCCESS);
    }
    unsigned char out[16];
    for (int i = 1; i <= 2; ++i) {
        ms_ecall_show_wallet_t m = {.ms_master_password="ok", .ms_master_password_len=3,
            .ms_wallet=(wallet_t *)out, .ms_wallet_size=sizeof(out)};
        tracking=1; alloc_count=0; fail_at=i;
        int previous=app_calls;
        assert(sgx_ecall_show_wallet(&m)==SGX_ERROR_OUT_OF_MEMORY);
        assert(app_calls==previous && live_count==0);
        fail_at=0; tracking=0;
        assert(create("ok",3)==SGX_SUCCESS);
    }
    /* Failure in the SDK's output copy after the app must release both buffers. */
    ms_ecall_show_wallet_t m = {.ms_master_password="ok", .ms_master_password_len=3,
        .ms_wallet=(wallet_t *)out, .ms_wallet_size=sizeof(out)};
    bridge_copy_fail=4; tracking=1; alloc_count=0;
    assert(sgx_ecall_show_wallet(&m)==SGX_ERROR_UNEXPECTED && live_count==0);
    bridge_copy_fail=0; tracking=0;
    assert(create("ok",3)==SGX_SUCCESS);
    persistent = app_alloc(16); memset(app_raw(persistent,16), 0x31,16);
    nested = 1;
    for (int i=0; i<8; ++i) assert(create("ok",3)==SGX_SUCCESS);
    assert(((char *)app_raw(persistent,16))[0] == 0x31);
}
static void ocalls(void)
{
    void *p = app_alloc(16), *result = app_alloc(sizeof(int));
    strcpy(app_raw(p,16), "hello");
    assert(ocall_debug_print(p) == SGX_SUCCESS && !strcmp(observed,"hello"));
    assert(ocall_debug_print(NULL) == SGX_SUCCESS && seen_null);
    assert(ocall_save_wallet(result, p, 6) == SGX_SUCCESS && seen_size == 6);
    assert(*(int *)app_raw(result,sizeof(int)) == 91);
    assert(ocall_save_wallet(NULL, NULL, 12) == SGX_SUCCESS && seen_null);
    assert(ocall_save_wallet(NULL, p, 0) == SGX_SUCCESS && !seen_null && seen_size == 0);
    assert(ocall_load_wallet(result, p, 16) == SGX_SUCCESS);
    assert(((unsigned char *)app_raw(p,16))[15] == 0x5a && *(int *)app_raw(result,4)==92);
    assert(ocall_is_wallet(result) == SGX_SUCCESS && *(int *)app_raw(result,4)==93);
    host_fail = 1; memset(app_raw(p,16),0x25,16);
    assert(ocall_load_wallet(result,p,16) == SGX_ERROR_UNEXPECTED);
    assert(((unsigned char *)app_raw(p,16))[0] == 0x25 && !ocbuf);
    host_fail = 0; ocalloc_fail = 1;
    assert(ocall_load_wallet(result,p,16) == SGX_ERROR_UNEXPECTED && !ocbuf);
    ocalloc_fail = 0;
    bridge_copy_fail=1;
    assert(ocall_save_wallet(result,p,16)==SGX_ERROR_UNEXPECTED && !ocbuf);
    bridge_copy_fail=0;
#ifdef ENCBOUND_PROTECTED
    int *cpu = (int *)encbound_enclave_base(); /* fake SDK trusted storage */
#else
    int cpu_local[4] = {0};
    int *cpu = cpu_local;
#endif
    assert(sgx_oc_cpuidex(cpu,0,0)==SGX_SUCCESS);
    /* SDK-only [user_check] pointers never pass through capability decoding. */
}
#ifdef ENCBOUND_PROTECTED
static void failures(void)
{
    void *p = app_alloc(16); uintptr_t raw=(uintptr_t)app_raw(p,16);
    uintptr_t bad[] = {raw, encbound_enclave_base(), (uintptr_t)p + 15};
    for (int i=0;i<3;++i) {
        fake_abort_active=1; int previous=host_calls;
        if (!setjmp(fake_abort_env)) {
            ocall_save_wallet(NULL,(const uint8_t *)bad[i],2); assert(!"missing protection abort");
        }
        fake_abort_active=0; assert(host_calls==previous && !ocbuf);
    }
    fake_abort_active=1;
    if (!setjmp(fake_abort_env)) {
        ocall_is_wallet((int *)raw); assert(!"unchecked result pointer");
    }
    fake_abort_active=0;
    memset((void *)raw,'a',16); fake_abort_active=1;
    if (!setjmp(fake_abort_env)) { ocall_debug_print(p); assert(!"unbounded string"); }
    fake_abort_active=0; assert(fake_abort_code==ENCBOUND_ERR_RANGE);
#ifdef ENCBOUND_MAC27
    fake_abort_active=1;
    if (!setjmp(fake_abort_env)) {
        ocall_save_wallet(NULL,(void *)((uintptr_t)p ^ (1ull<<32)),1);
        assert(!"forged tag accepted");
    }
    fake_abort_active=0; assert(fake_abort_code==ENCBOUND_ERR_TAG);
#endif
}
static void failed_init(void)
{
    init_fail=1;
    assert(create("ok",3)==SGX_ERROR_UNEXPECTED);
    init_fail=0;
    assert(create("ok",3)==SGX_ERROR_ECALL_NOT_ALLOWED && app_calls==0);
}
#endif
static void run(const char *name, void (*test)(void), int initialize)
{
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
#ifdef ENCBOUND_PROTECTED
        if (initialize) { assert(create("warm",5)==SGX_SUCCESS); app_calls=0; }
#else
        (void)initialize;
#endif
        test(); _exit(0);
    }
    int status; assert(waitpid(pid,&status,0)==pid);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr,"FAIL: %s status=%d\n",name,status); exit(1);
    }
    printf("PASS: %s\n",name);
}
int main(void)
{
    run("SDK input semantics and removed caps",inputs,1);
    run("SDK output/error semantics and original byte geometry",outputs,1);
    run("allocation/copy failure cleanup and session ownership",cleanup,1);
    run("actual OCALL proxies and SDK-only raw ABI",ocalls,1);
#ifdef ENCBOUND_PROTECTED
    run("proxy protection before raw access",failures,1);
    run("initialization failure is terminal",failed_init,0);
#endif
    puts("MODIFIED BRIDGE NATIVE PASS");
}
