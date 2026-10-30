#ifndef ENCBOUND_YEEZ_ADAPTERS_H
#define ENCBOUND_YEEZ_ADAPTERS_H
#include <stddef.h>
#include <stdint.h>
#include <sgx_dh.h>
#include <sgx_tcrypto.h>
#ifdef __cplusplus
extern "C" {
#endif
sgx_status_t yeez_read_rand(unsigned char *, size_t);
sgx_status_t yeez_encrypt(const sgx_aes_gcm_128bit_key_t *, const uint8_t *, uint32_t,
    uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint32_t, sgx_aes_gcm_128bit_tag_t *);
sgx_status_t yeez_decrypt(const sgx_aes_gcm_128bit_key_t *, const uint8_t *, uint32_t,
    uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint32_t, const sgx_aes_gcm_128bit_tag_t *);
sgx_status_t yeez_cmac(const sgx_cmac_128bit_key_t *, const uint8_t *, uint32_t, sgx_cmac_128bit_tag_t *);
sgx_status_t yeez_sha256(const uint8_t *, uint32_t, sgx_sha256_hash_t *);
int yeez_memset_s(void *, size_t, int, size_t);
sgx_status_t yeez_dh_init(sgx_dh_session_role_t, sgx_dh_session_t *);
sgx_status_t yeez_dh_msg1(const sgx_dh_msg1_t *, sgx_dh_msg2_t *, sgx_dh_session_t *);
sgx_status_t yeez_dh_msg3(const sgx_dh_msg3_t *, sgx_dh_session_t *, sgx_key_128bit_t *,
    sgx_dh_session_enclave_identity_t *);
#ifdef __cplusplus
}
#endif
#endif
