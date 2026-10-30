/* Exact checked services for the RA boundary fixture. No raw SDK state escapes.
 * This does not establish the complete SGX-KMS service closure. */
#include <string.h>
#include <sgx_tkey_exchange.h>
#include <sgx_utils.h>
#include "encbound_runtime.h"
#ifndef ENCBOUND_PROTECTED
#define encbound_fixture_ra_init fixture_ra_init
#define encbound_fixture_ra_keys fixture_ra_keys
#define encbound_fixture_ra_close fixture_ra_close
#endif
static void *range(const void *p, size_t n, int kind)
{
#ifdef ENCBOUND_PROTECTED
    return (void *)encbound_require((uintptr_t)p, n, kind);
#else
    (void)n; (void)kind; return (void *)p;
#endif
}
sgx_status_t encbound_fixture_ra_init(sgx_ec256_public_t *key, sgx_ra_context_t *context,
                                    sgx_target_info_t *target)
{
    if (!key || !context || !target) return SGX_ERROR_INVALID_PARAMETER;
    const void *input = range(key, sizeof(*key), ENCBOUND_ACCESS_READ);
    void *output = range(context, sizeof(*context), ENCBOUND_ACCESS_WRITE);
    void *target_output = range(target, sizeof(*target), ENCBOUND_ACCESS_WRITE);
    sgx_ec256_public_t local_key;
    sgx_ra_context_t local_context = 0;
    sgx_target_info_t local_target = {0};
    memcpy(&local_key, input, sizeof(local_key));
    sgx_status_t status = sgx_self_target(&local_target);
    if (status == SGX_SUCCESS) status = sgx_ra_init(&local_key, 0, &local_context);
    if (status == SGX_SUCCESS) {
        memcpy(output, &local_context, sizeof(local_context));
        memcpy(target_output, &local_target, sizeof(local_target));
    }
    return status;
}
sgx_status_t encbound_fixture_ra_keys(sgx_ra_context_t context, sgx_ra_key_type_t type, sgx_ra_key_128_t *key)
{
    if (!key) return SGX_ERROR_INVALID_PARAMETER;
    void *output = range(key, sizeof(*key), ENCBOUND_ACCESS_WRITE);
    sgx_ra_key_128_t local = {0};
    sgx_status_t status = sgx_ra_get_keys(context, type, &local);
    if (status == SGX_SUCCESS) memcpy(output, &local, sizeof(local));
    memset_s(&local, sizeof(local), 0, sizeof(local));
    return status;
}
sgx_status_t encbound_fixture_ra_close(sgx_ra_context_t context)
{ return sgx_ra_close(context); }
