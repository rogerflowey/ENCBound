#ifndef USIG_ENCLAVE_T_H
#define USIG_ENCLAVE_T_H
#include <stdint.h>
#include <sgx_tcrypto.h>
#ifdef __cplusplus
extern "C" {
#endif
sgx_status_t ecall_usig_init(const char *, uint32_t, sgx_ec256_private_t,
                            uint32_t, const char *, uint32_t);
sgx_status_t ecall_usig_create_ui_sig(sgx_sha256_hash_t, uint64_t *,
                                      sgx_ec256_signature_t *);
sgx_status_t ecall_usig_create_ui_mac(sgx_sha256_hash_t, uint64_t *,
                                      uint8_t *, uint32_t);
sgx_status_t ecall_usig_verify_ui_mac(sgx_sha256_hash_t, uint64_t,
                                      const uint8_t *, uint32_t, uint8_t *);
sgx_status_t ecall_usig_create_ui_sig_edd25519(sgx_sha256_hash_t, uint32_t,
                                               uint64_t *, uint8_t *,
                                               uint32_t);
void ocall_print_string(const char *str);
#ifdef __cplusplus
}
#endif
#endif
