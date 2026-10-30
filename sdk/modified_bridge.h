/* ENCBound-aware Intel bridge primitives. Trusted; never application APIs.
 * The generated bridge owns each allocation and its raw/capability aliases. */
#ifndef ENCBOUND_MODIFIED_BRIDGE_H
#define ENCBOUND_MODIFIED_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#include <sgx_error.h>
#include "boundary_support.h"
#include "encbound_runtime.h"
#include "encbound_platform.h"

static inline sgx_status_t encbound_bridge_enter(void)
{
    if (encbound_boundary_admit() != 0)
        return SGX_ERROR_ECALL_NOT_ALLOWED;
    if (encbound_boundary_initialize() != 0) {
        encbound_boundary_fail();
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

static inline void *encbound_bridge_alloc(size_t n, void **cap)
{
    *cap = encbound_boundary_alloc(n);
    return *cap ? encbound_boundary_write(*cap, n) : NULL;
}

static inline void *encbound_bridge_range(const void *cap, size_t n, int kind)
{
    uintptr_t p = (uintptr_t)cap;
    if (!cap) return NULL; /* Intel conditionally marshals NULL arguments. */
    if (n == 0) {
        /* No access is authorized. Convert representation solely for Intel's
         * zero-length enclosure test/copy. The raw value stays in the trusted
         * proxy and is used only with this unchanged zero byte count. No MAC
         * check or invented one-byte access is needed for a zero-byte copy. */
        unsigned radix = p >> 59;
        return (void *)(radix > 0 && radix < 31
            ? encbound_enclave_base() + (uint32_t)p : p);
    }
    return (void *)encbound_require(p, n, kind);
}

static inline void *encbound_bridge_string(const void *cap, size_t unit)
{
    uintptr_t raw;
    size_t available, i, j;
    int result;
    if (!cap) return NULL;
    result = encbound_check_extent((uintptr_t)cap, &raw, &available);
    if (result != ENCBOUND_OK) encbound_abort(result);
    /* Scan complete char/wchar_t code units within the admitted extent. Byte
     * accesses also handle a short, unaligned tail without reading past it. */
    if (unit == 0 || unit > available) encbound_abort(ENCBOUND_ERR_RANGE);
    for (i = 0; i <= available - unit; i += unit) {
        for (j = 0; j < unit; ++j)
            if (((const unsigned char *)raw)[i + j] != 0) break;
        if (j == unit) return (void *)raw;
    }
    encbound_abort(ENCBOUND_ERR_RANGE);
}
#endif
