/* Local stand-ins for the native dig.  They are not real SGX services and do
 * not establish crypto behavior.  The signed Ed25519 stub only writes the
 * output sizes/layout used by the application's length checks. */
#include <stdint.h>
#include <string.h>
#include <sgx_tcrypto.h>
#include "edd25519/crypto_api.h"

extern "C" void ocall_print_string(const char *s) { (void)s; }

sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t *h)
{
    *h = (sgx_ecc_state_handle_t)0x1234;
    return SGX_SUCCESS;
}

sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t h)
{
    (void)h;
    return SGX_SUCCESS;
}

sgx_status_t sgx_ecdsa_sign(const uint8_t *d, uint32_t n,
                            const sgx_ec256_private_t *k,
                            sgx_ec256_signature_t *s,
                            sgx_ecc_state_handle_t h)
{
    (void)d; (void)n; (void)k; (void)h;
    memset(s, 0, sizeof(*s));
    return SGX_SUCCESS;
}

sgx_status_t sgx_hmac_sha256_msg(const unsigned char *s, int sn,
                                 const unsigned char *k, int kn,
                                 unsigned char *m, int mn)
{
    (void)s; (void)sn; (void)k; (void)kn;
    if (mn < 1 || mn > 32) {
        if (m && mn > 0)
            memset(m, 0, (size_t)mn);
        return SGX_ERROR_UNEXPECTED;
    }
    memset(m, 0x5a, (size_t)mn);
    return SGX_SUCCESS;
}

sgx_status_t sgx_read_rand(unsigned char *p, size_t n)
{
    memset(p, 0x42, n);
    return SGX_SUCCESS;
}

int crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *sk)
{
    (void)sk;
    memset(sm, 0x11, 64);
    memcpy(sm + 64, m, (size_t)mlen);
    *smlen = mlen + 64;
    return 0;
}
