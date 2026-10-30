/* Trusted diagnostic entry and scalar observer, like sdk/forgery_probe.c.
 * One invocation per enclave, including BASELINE. No allocation or mint service
 * is exported to application code. Exit requests remain terminal and are never
 * classified as an ENCBound rejection.
 */
#include "juliet_t.h"
#include "encbound_runtime.h"
extern int juliet_dispatch(uint32_t case_id, uint32_t bad);
static int used;

void juliet_emit(uint32_t kind, uint64_t value)
{
    /* Only the documented output event kinds are accepted. */
    if (kind < 1 || kind > 8 || juliet_observe(kind, value) != SGX_SUCCESS)
        __builtin_trap();
}
_Noreturn void juliet_exit(int status)
{
    (void)juliet_observe(102, (uint64_t)(int64_t)status);
    __builtin_trap();
    for (;;) {}
}
int juliet_run(uint32_t case_id, uint32_t bad)
{
    if (used || bad > 1) return 90;
    used = 1;
#ifndef JULIET_BASELINE
    if (encbound_runtime_init() != 0) return 91;
#endif
    if (juliet_observe(100, case_id) != SGX_SUCCESS) return 92;
    int result = juliet_dispatch(case_id, bad);
    if (juliet_observe(101, case_id) != SGX_SUCCESS) return 93;
    return result;
}
