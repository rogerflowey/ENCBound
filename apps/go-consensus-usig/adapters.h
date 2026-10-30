#ifndef ENCBOUND_USIG_ADAPTERS_H
#define ENCBOUND_USIG_ADAPTERS_H
#include <stddef.h>
#include <stdint.h>
#include <sgx_tcrypto.h>
sgx_status_t encbound_usig_ecc_open(sgx_ecc_state_handle_t *);
sgx_status_t encbound_usig_ecc_close(sgx_ecc_state_handle_t);
sgx_status_t encbound_usig_ecdsa_sign(const uint8_t *, uint32_t, const sgx_ec256_private_t *, sgx_ec256_signature_t *, sgx_ecc_state_handle_t);
sgx_status_t encbound_usig_hmac(const unsigned char *, int, const unsigned char *, int, unsigned char *, int);
sgx_status_t encbound_usig_rand(unsigned char *, size_t);
#endif
