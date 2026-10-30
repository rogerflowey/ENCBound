/*
 * ENCBound restart - native fixture bridge header for generated adapter tests
 * (docs/legacy/steps/09-original-api-and-sessions.md).
 *
 * This stands in for the Intel sgx_edger8r-generated enclave_t.h when the
 * generated ECALL/OCALL C (tools/encbound_edl.py) is compiled and run natively.
 *
 * It declares the five original public ECALLs exactly as Intel's trusted bridge
 * does (application `int` return, no SGX_CDECL) and the four raw OCALL bridge
 * entry points with Intel's trusted OCALL ABI: for a non-void OCALL the return
 * is transported through an added `int *retval` first argument. The native tests
 * provide recording stubs so that a mis-decoded (still tagged) address faults.
 *
 * This is a test fixture, not a replacement EDL. The application build still
 * compiles the generated adapters against the real pinned enclave_t.h.
 */

#ifndef ENCBOUND_TEST_OcallMockEnclaveT
#define ENCBOUND_TEST_OcallMockEnclaveT

#include <stddef.h>
#include <stdint.h>

#include <sgx_defs.h>
#include <sgx_error.h>

#include "wallet.h"

/* The original public ECALLs, as Intel's generated enclave_t.h declares them. */
int ecall_create_wallet(const char *master_password);
int ecall_show_wallet(const char *master_password, wallet_t *wallet,
                      size_t wallet_size);
int ecall_change_master_password(const char *old_password,
                                 const char *new_password);
int ecall_add_item(const char *master_password, const item_t *item,
                   size_t item_size);
int ecall_remove_item(const char *master_password, int index);

sgx_status_t SGX_CDECL ocall_debug_print(const char *str);

sgx_status_t SGX_CDECL ocall_save_wallet(int *retval,
                                         const uint8_t *sealed_data,
                                         size_t sealed_size);

sgx_status_t SGX_CDECL ocall_load_wallet(int *retval, uint8_t *sealed_data,
                                         size_t sealed_size);

sgx_status_t SGX_CDECL ocall_is_wallet(int *retval);

#endif /* ENCBOUND_TEST_OcallMockEnclaveT */
