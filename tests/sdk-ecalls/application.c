/* Boundary fixture only; these are not upstream SGX-KMS application bodies. */
#include "probe_t.h"
extern sgx_status_t fixture_ra_init(sgx_ec256_public_t *, sgx_ra_context_t *, sgx_target_info_t *);
extern sgx_status_t fixture_ra_keys(sgx_ra_context_t, sgx_ra_key_type_t, sgx_ra_key_128_t *);
extern sgx_status_t fixture_ra_close(sgx_ra_context_t);
static uint32_t starts;
sgx_status_t session_start(sgx_ec256_public_t *key, sgx_ra_context_t *context, sgx_target_info_t *target)
{
    sgx_status_t status = fixture_ra_init(key, context, target);
    if (status == SGX_SUCCESS) ++starts;
    return status;
}
sgx_status_t session_key(sgx_ra_context_t context, sgx_ra_key_type_t type, sgx_ra_key_128_t *key)
{ return fixture_ra_keys(context, type, key); }
sgx_status_t session_close(sgx_ra_context_t context)
{ return fixture_ra_close(context); }
uint32_t session_count(void) { return starts; }
