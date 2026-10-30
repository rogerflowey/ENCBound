/* App-specific instance of apps/botscreen/entropy.c's checked SDK adapter.
 * Trusted code: validate the entire destination, then call the pinned SDK.
 * No raw SDK object is returned to the application. */
#include <stddef.h>
#include <stdint.h>
#include "encbound_common.h"
#include "encbound_runtime.h"
extern uint32_t sgx_read_rand(unsigned char *, size_t);

uint32_t encbound_conflow_rand(unsigned char *buffer, size_t length)
{
#ifndef ENCBOUND_CXX_BASELINE
    uintptr_t raw = encbound_require((uintptr_t)buffer, length, ENCBOUND_ACCESS_WRITE);
    return sgx_read_rand((unsigned char *)raw, length);
#else
    return sgx_read_rand(buffer, length);
#endif
}
