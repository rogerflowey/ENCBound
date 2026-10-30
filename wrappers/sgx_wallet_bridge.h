/*
 * ENCBound restart - raw trusted OCALL entry points for the pinned sgx-wallet
 * EDL (enclave/enclave.edl, sha256
 * 52c9b4d09c2eaa7d68de60d304cba97548fd774f2430331bb6cbeecde7082d42).
 *
 * These are the ordinary sgx_edger8r-generated bridge functions. They expect
 * raw enclave addresses; the step 5 adapters in wrappers/sdk_adapters.c decode
 * application capabilities and validate complete ranges before calling them.
 *
 * The app enclave build defines ENCBOUND_APP_ENCLAVE and includes the
 * authoritative generated enclave_t.h. Native adapter tests use the
 * declarations below so they can interpose the bridges. This header is a
 * dependency inventory of the boundary, not a replacement for the EDL.
 */

#ifndef ENCBOUND_SGX_WALLET_BRIDGE_H
#define ENCBOUND_SGX_WALLET_BRIDGE_H

#ifdef ENCBOUND_APP_ENCLAVE
#include "enclave_t.h"
#else
#include <stddef.h>
#include <stdint.h>

#include <sgx_defs.h>

sgx_status_t SGX_CDECL ocall_debug_print(const char *str);
sgx_status_t SGX_CDECL ocall_save_wallet(int *retval,
                                         const uint8_t *sealed_data,
                                         size_t sealed_size);
sgx_status_t SGX_CDECL ocall_load_wallet(int *retval, uint8_t *sealed_data,
                                         size_t sealed_size);
sgx_status_t SGX_CDECL ocall_is_wallet(int *retval);
#endif /* ENCBOUND_APP_ENCLAVE */

#endif /* ENCBOUND_SGX_WALLET_BRIDGE_H */
