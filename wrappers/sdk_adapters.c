/*
 * ENCBound restart - step 5 SDK sealing and sgx-wallet OCALL adapters (trusted).
 *
 * These complete the private application-to-library boundary for the sgx-wallet
 * candidate. They are ordinary trusted code and are never passed through the
 * instrumentation pass. Each adapter:
 *   * treats every application argument as a capability, never as an address;
 *   * validates the complete range the raw callee may read or write before
 *     decoding, using the checked runtime API;
 *   * calls the raw SDK/bridge routine only on decoded addresses; and
 *   * does not return or expose a raw address to application code.
 *
 * Failure categories that indicate an application pointer-geometry or policy
 * violation invoke encbound_abort(). Failures that describe an untrusted host
 * reply (a corrupt sealed blob, an undersized caller buffer) are returned as
 * ordinary SGX status, matching the SDK's own behavior, so the application can
 * follow its normal error path. See docs/legacy/contracts/library-adapters.md.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sgx_defs.h>
#include <sgx_tseal.h>

#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"

#include "encbound_adapters.h"

#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffU
#endif

/*
 * Seal: the application supplies the plaintext wallet and a sealed output
 * buffer. Validate the encrypted input, the optional additional-MAC input, and
 * the whole sealed output range, then call the raw SDK routine.
 */
sgx_status_t encbound_sgx_seal_data(uint32_t additional_MACtext_length,
                                    const uint8_t *p_additional_MACtext,
                                    uint32_t text2encrypt_length,
                                    const uint8_t *p_text2encrypt,
                                    uint32_t sealed_data_size,
                                    sgx_sealed_data_t *p_sealed_data)
{
    uintptr_t text_raw;
    uintptr_t add_raw = 0;
    uintptr_t sealed_raw;

    if (text2encrypt_length == 0 || p_text2encrypt == NULL ||
        sealed_data_size == 0 || p_sealed_data == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (additional_MACtext_length == 0) {
        if (p_additional_MACtext != NULL) {
            /* The SDK reads nothing for zero length; refuse the ambiguous
               shape rather than leak an undecoded pointer. */
            return SGX_ERROR_INVALID_PARAMETER;
        }
    } else {
        if (p_additional_MACtext == NULL) {
            return SGX_ERROR_INVALID_PARAMETER;
        }
        add_raw = encbound_require((uintptr_t)p_additional_MACtext,
                                   (size_t)additional_MACtext_length,
                                   ENCBOUND_ACCESS_READ);
    }

    text_raw = encbound_require((uintptr_t)p_text2encrypt,
                                (size_t)text2encrypt_length,
                                ENCBOUND_ACCESS_READ);
    sealed_raw = encbound_require((uintptr_t)p_sealed_data,
                                  (size_t)sealed_data_size,
                                  ENCBOUND_ACCESS_WRITE);

    return sgx_seal_data(additional_MACtext_length,
                         (const uint8_t *)add_raw, text2encrypt_length,
                         (const uint8_t *)text_raw, sealed_data_size,
                         (sgx_sealed_data_t *)sealed_raw);
}

/*
 * Unseal: the sealed blob is host-controlled. The SDK derives its input length
 * from header fields inside that blob, so a raw passthrough could read past the
 * object the application exposed. Bound the claimed blob to the validated
 * extent of the application capability first, then validate the plaintext and
 * optional additional-MAC output ranges before decoding anything for the SDK.
 */
sgx_status_t encbound_sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data,
                                      uint8_t *p_additional_MACtext,
                                      uint32_t *p_additional_MACtext_length,
                                      uint8_t *p_decrypted_text,
                                      uint32_t *p_decrypted_text_length)
{
    uintptr_t sealed_raw;
    uintptr_t add_raw = 0;
    uintptr_t add_len_raw = 0;
    uintptr_t text_raw;
    uintptr_t text_len_raw;
    size_t sealed_remaining;
    uint32_t enc_len;
    uint32_t add_len;
    uint32_t total;
    uint32_t capacity;
    int rc;

    if (p_sealed_data == NULL || p_decrypted_text == NULL ||
        p_decrypted_text_length == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    rc = encbound_check_extent((uintptr_t)p_sealed_data, &sealed_raw,
                               &sealed_remaining);
    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
    if (sealed_remaining < sizeof(sgx_sealed_data_t)) {
        return SGX_ERROR_MAC_MISMATCH;
    }

    enc_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_raw);
    add_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_raw);
    if (enc_len == UINT32_MAX || add_len == UINT32_MAX) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    total = sgx_calc_sealed_data_size(add_len, enc_len);
    if (total == UINT32_MAX || (size_t)total > sealed_remaining) {
        return SGX_ERROR_MAC_MISMATCH;
    }
    if (enc_len == 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /* The caller's declared plaintext capacity is an in/out scalar. */
    text_len_raw = encbound_require((uintptr_t)p_decrypted_text_length,
                                    sizeof(*p_decrypted_text_length),
                                    ENCBOUND_ACCESS_READWRITE);
    capacity = *(const uint32_t *)text_len_raw;
    if (capacity < enc_len) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    text_raw = encbound_require((uintptr_t)p_decrypted_text, (size_t)enc_len,
                                ENCBOUND_ACCESS_WRITE);

    if (add_len > 0) {
        if (p_additional_MACtext == NULL ||
            p_additional_MACtext_length == NULL) {
            return SGX_ERROR_INVALID_PARAMETER;
        }
        add_len_raw = encbound_require((uintptr_t)p_additional_MACtext_length,
                                       sizeof(*p_additional_MACtext_length),
                                       ENCBOUND_ACCESS_READWRITE);
        if (*(const uint32_t *)add_len_raw < add_len) {
            return SGX_ERROR_INVALID_PARAMETER;
        }
        add_raw = encbound_require((uintptr_t)p_additional_MACtext,
                                   (size_t)add_len, ENCBOUND_ACCESS_WRITE);
    } else if (p_additional_MACtext != NULL ||
               p_additional_MACtext_length != NULL) {
        /* The blob carries no additional MAC text; refuse the ambiguous
           shape rather than pass an undecoded pointer to the SDK. */
        return SGX_ERROR_INVALID_PARAMETER;
    }

    return sgx_unseal_data((const sgx_sealed_data_t *)sealed_raw,
                           (uint8_t *)add_raw, (uint32_t *)add_len_raw,
                           (uint8_t *)text_raw, (uint32_t *)text_len_raw);
}

/*
 * The four sgx-wallet OCALL adapters (ocall_is_wallet, ocall_save_wallet,
 * ocall_load_wallet, ocall_debug_print) are no longer handwritten here. They
 * are generated by tools/encbound_edl.py from the wallet EDL and the explicit
 * boundary-policy.json, and compiled from build/.../encbound-generated. See
 * docs/legacy/steps/08-edl-generation.md. This translation unit keeps only the
 * service-specific SDK sealing adapters, whose contracts EDL does not carry.
 */
