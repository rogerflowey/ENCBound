#ifndef SK_T_H__
#define SK_T_H__

/*
 * Minimal trusted-function declarations for the native, non-SGX ASan
 * differential harness.  The pinned enclave source includes "sk_t.h"; the
 * SDK-sim builds use the edger8r-generated header instead.
 */
#include <stddef.h>
#include <stdint.h>

int ecall_sk_get_key_handle_len_ed25519(const char *application,
    size_t *key_handle_len);
int ecall_sk_enroll_ed25519(const char *application, uint8_t *public_key,
    size_t public_key_len, uint8_t *key_handle, size_t key_handle_len);
int ecall_sk_sign_ed25519(const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, uint32_t *counter, uint8_t *sig_r, size_t sig_r_len);

#endif
