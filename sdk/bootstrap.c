/*
 * ENCBound restart - step 1 trusted bootstrap.
 *
 * Ordinary, uninstrumented byte transformation executed inside the enclave.
 * There is deliberately no ENCBound pointer, tag, or check yet: this only
 * proves that an ECALL we define actually runs in the enclave.
 */

#include "request_t.h"

#include "encbound_platform.h"

#define APP_OK 0
#define APP_ERR_BAD_ARG 1
#define APP_ERR_CAPACITY 2
#define APP_ERR_PLATFORM 3

sgx_status_t encbound_process(const uint8_t *input, uint32_t input_len,
                              uint8_t *output, uint32_t output_capacity,
                              uint32_t *output_len, int32_t *app_status)
{
    uint32_t i;

    if (output_len == NULL || app_status == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    *output_len = 0u;
    *app_status = APP_ERR_BAD_ARG;

    /* Initialize trusted state once per instance before any app work. */
    if (encbound_platform_init() != 0) {
        *app_status = APP_ERR_PLATFORM;
        return SGX_SUCCESS;
    }

    if (input_len != 0u && input == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (output_capacity != 0u && output == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (input_len > output_capacity) {
        *app_status = APP_ERR_CAPACITY;
        return SGX_SUCCESS;
    }

    for (i = 0u; i < input_len; ++i) {
        output[i] = input[input_len - 1u - i];
    }

    *output_len = input_len;
    *app_status = APP_OK;
    return SGX_SUCCESS;
}
