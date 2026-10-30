/*
 * ENCBound restart - upstream host compatibility shim
 * (docs/legacy/steps/09-original-api-and-sessions.md).
 *
 * The pinned upstream host source app/app.cpp does `#include "ocalls.h"`, but
 * that header is absent from the pinned tree. This ENCBound-owned shim supplies
 * it on the include path so the pinned app/app.cpp, app/test.cpp and app/utils.cpp
 * can be compiled byte-for-byte unchanged. It declares the four OCALLs the
 * upstream host defines; the generated enclave_u.h already declares them with
 * C linkage, so this header only makes the missing upstream file explicit.
 *
 * This is untrusted host compatibility material, not part of the protected
 * interface, and no pinned source is edited.
 */

#ifndef ENCBOUND_UPSTREAM_OCALLS_SHIM_H
#define ENCBOUND_UPSTREAM_OCALLS_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void ocall_debug_print(const char *str);
int ocall_save_wallet(const uint8_t *sealed_data, const size_t sealed_size);
int ocall_load_wallet(uint8_t *sealed_data, const size_t sealed_size);
int ocall_is_wallet(void);

#ifdef __cplusplus
}
#endif

#endif /* ENCBOUND_UPSTREAM_OCALLS_SHIM_H */
