/*
 * ENCBound restart - auxiliary AddressSanitizer reproduction (step 0).
 *
 * Compiles the real sgx-wallet enclave source (enclave.cpp) natively with the
 * SDK-free stubs below and calls ecall_show_wallet with a deliberately small
 * output buffer. ASan reports the exact bad access at the statement
 * `(*wallet) = *unsealed_wallet` in enclave.cpp.
 *
 * This is diagnostic evidence that the bad access exists in the application
 * source. It is not an SGX execution and not an ENCBound result.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wallet.h"
#include "enclave.h"
#include "sgx_tseal.h"
#include "enclave_t.h"

static wallet_t g_stored;

sgx_status_t SGX_CDECL ocall_debug_print(const char *str)
{
    (void)str;
    return SGX_SUCCESS;
}

sgx_status_t SGX_CDECL ocall_save_wallet(int *retval, const uint8_t *sealed_data,
                                         size_t sealed_size)
{
    (void)sealed_data;
    (void)sealed_size;
    *retval = 0;
    return SGX_SUCCESS;
}

sgx_status_t SGX_CDECL ocall_load_wallet(int *retval, uint8_t *sealed_data,
                                         size_t sealed_size)
{
    (void)sealed_data;
    (void)sealed_size;
    *retval = 0;
    return SGX_SUCCESS;
}

sgx_status_t SGX_CDECL ocall_is_wallet(int *retval)
{
    *retval = 0;
    return SGX_SUCCESS;
}

/* Stand-ins for the trusted sealing service. */
sgx_status_t SGXAPI sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data,
                                    uint8_t *p_additional_MACtext,
                                    uint32_t *p_additional_MACtext_length,
                                    uint8_t *p_decrypted_text,
                                    uint32_t *p_decrypted_text_length)
{
    (void)p_sealed_data;
    (void)p_additional_MACtext;
    (void)p_additional_MACtext_length;
    memcpy(p_decrypted_text, &g_stored, sizeof(g_stored));
    *p_decrypted_text_length = (uint32_t)sizeof(g_stored);
    return SGX_SUCCESS;
}

sgx_status_t SGXAPI sgx_seal_data(const uint32_t additional_MACtext_length,
                                  const uint8_t *p_additional_MACtext,
                                  const uint32_t text2encrypt_length,
                                  const uint8_t *p_text2encrypt,
                                  const uint32_t sealed_data_size,
                                  sgx_sealed_data_t *p_sealed_data)
{
    (void)additional_MACtext_length;
    (void)p_additional_MACtext;
    (void)text2encrypt_length;
    (void)p_text2encrypt;
    (void)sealed_data_size;
    (void)p_sealed_data;
    return SGX_SUCCESS;
}

int main(void)
{
    uint8_t *buffer;
    int ret = -123;

    memset(&g_stored, 0, sizeof(g_stored));
    strcpy(g_stored.master_password, "password123");
    g_stored.size = 0;

    buffer = (uint8_t *)malloc(16);
    if (buffer == NULL) {
        return 2;
    }
    printf("ecall_show_wallet: sizeof(wallet_t)=%zu wallet_size=16\n",
           sizeof(wallet_t));
    fflush(stdout);

    ret = ecall_show_wallet("password123", (wallet_t *)buffer, 16);
    printf("returned %d\n", ret);
    free(buffer);
    return 0;
}
