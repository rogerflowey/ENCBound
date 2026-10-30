/*
 * ENCBound restart - step 5 SDK sealing and sgx-wallet OCALL adapter
 * prototypes. Trusted code; selected only by build-inventory redirection of
 * instrumented application call sites. See docs/legacy/contracts/library-adapters.md.
 */

#ifndef ENCBOUND_ADAPTERS_H
#define ENCBOUND_ADAPTERS_H

#include <stddef.h>
#include <stdint.h>

#include <sgx_tseal.h>

/* sgx_seal_data / sgx_unseal_data checked adapters. Same signatures as the SDK
 * API so the pass can retarget the call without a type change. */
sgx_status_t encbound_sgx_seal_data(uint32_t additional_MACtext_length,
                                    const uint8_t *p_additional_MACtext,
                                    uint32_t text2encrypt_length,
                                    const uint8_t *p_text2encrypt,
                                    uint32_t sealed_data_size,
                                    sgx_sealed_data_t *p_sealed_data);

sgx_status_t encbound_sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data,
                                      uint8_t *p_additional_MACtext,
                                      uint32_t *p_additional_MACtext_length,
                                      uint8_t *p_decrypted_text,
                                      uint32_t *p_decrypted_text_length);

/*
 * The four sgx-wallet OCALL adapter declarations now live in the generated
 * encbound_boundary.h (tools/encbound_edl.py). Include that header where the
 * generated OCALL adapters are used.
 */

#endif /* ENCBOUND_ADAPTERS_H */
