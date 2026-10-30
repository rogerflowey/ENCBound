#ifndef ENCBOUND_SK_SGX_ADAPTERS_H
#define ENCBOUND_SK_SGX_ADAPTERS_H

#include <stddef.h>
#include <stdint.h>
#include <sgx_tseal.h>

uint32_t encbound_sk_rand(unsigned char *, size_t);
uint32_t encbound_sk_calc_sealed_data_size(uint32_t, uint32_t);
uint32_t encbound_sk_get_encrypt_txt_len(const sgx_sealed_data_t *);
uint32_t encbound_sk_get_add_mac_txt_len(const sgx_sealed_data_t *);
int encbound_sk_consttime_memequal(const void *, const void *, size_t);
int encbound_sk_memset_s(void *, size_t, int, size_t);
sgx_status_t encbound_sk_seal_data(uint32_t, const uint8_t *, uint32_t,
                                  const uint8_t *, uint32_t, sgx_sealed_data_t *);
sgx_status_t encbound_sk_unseal_data(const sgx_sealed_data_t *, uint8_t *,
                                    uint32_t *, uint8_t *, uint32_t *);

#endif
