/*
 * SDK SIM control harness for the pinned sk-sgx sealed-handle read.
 *
 * h1 sends key_handle_len = 1.  In BASELINE the original enclave reads byte
 * 512 of the trusted one-byte copy; in RADIX_ONLY/MAC27 the checked sealing
 * adapter rejects the capability first.
 *
 * h2 sends a 516-byte handle whose plain_text_offset is 64.  BASELINE reads
 * payload_size at byte 528; a protected profile rounds the request to a
 * 1024-byte slot, so the same read stays inside that allocation and the
 * original application rejects the request with -1.
 *
 * This host is deliberately independent of the functional provider oracle.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_tseal.h>
#include <sgx_urts.h>

#include "sk_u.h"
#include "../four_app_permissions.h"

#define CHECK(x) do { \
    if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } \
} while (0)

void ocall_puts(const char *str)
{
    (void)str;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "h1";
    size_t aad_off = offsetof(sgx_sealed_data_t, plain_text_offset);
    size_t len;
    uint8_t *handle;
    uint8_t message[32] = {0};
    uint8_t sig_r[64] = {0};
    uint32_t counter = 0;
    sgx_enclave_id_t eid = 0;
    sgx_status_t status;
    size_t sealed_len = 0;
    int result = 777;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (strcmp(mode, "h1") == 0) {
        len = 1;
    } else if (strcmp(mode, "h2") == 0) {
        len = aad_off + sizeof(uint32_t);
    } else {
        fprintf(stderr, "usage: %s h1|h2\n", argv[0]);
        return 2;
    }

    handle = calloc(1, len);
    CHECK(handle != NULL);
    if (strcmp(mode, "h2") == 0) {
        uint32_t value = 64;
        memcpy(handle + aad_off, &value, sizeof value);
    }

    CHECK(sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL,
        &eid, NULL) == SGX_SUCCESS);
    four_app_permissions("enclave.signed.so");

    status = ecall_sk_get_key_handle_len_ed25519(eid, &result, "vuln",
        &sealed_len);
    CHECK(status == SGX_SUCCESS && result == 0);
    CHECK(sealed_len == sizeof(sgx_sealed_data_t) + 64 + 4);
    printf("VULN setup sealed=%zu handle_len=%zu aad_off=%zu\n",
        sealed_len, len, aad_off);

    status = ecall_sk_sign_ed25519(eid, &result, message, sizeof message,
        "vuln", handle, len, 1, &counter, sig_r, sizeof sig_r);
    printf("VULN %s completed status=%#x r=%d\n", mode, status, result);
    CHECK(status == SGX_SUCCESS);
    CHECK(result == -1);

    sgx_destroy_enclave(eid);
    free(handle);
    return 0;
}
