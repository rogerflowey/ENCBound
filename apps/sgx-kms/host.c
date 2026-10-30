/* SGX-KMS benign service/C16 host. Independent OpenSSL peer and loaded-page
 * checks adapted from tests/sdk-ecalls/host.c (original ENCBound support).
 * SDK SIM only; no protection, IAS, deployment or hardware claim. */
#include <assert.h>
#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#define SAMPLE_ECP_KEY_SIZE 32
#include "host_types.h"

static unsigned calls, verified_keys;
/* Same ELF/proc loaded-page method as tests/early-bootstrap/host.c. */
static void permissions(const char *image)
{
    FILE *f = fopen(image, "rb"); assert(f);
    Elf64_Ehdr eh; assert(fread(&eh, 1, sizeof eh, f) == sizeof eh);
    Elf64_Shdr *sh = malloc(eh.e_shnum*sizeof(*sh)); assert(sh);
    assert(fseek(f, eh.e_shoff, SEEK_SET) == 0);
    assert(fread(sh, sizeof(*sh), eh.e_shnum, f) == eh.e_shnum);
    char *names = malloc(sh[eh.e_shstrndx].sh_size); assert(names);
    assert(fseek(f, sh[eh.e_shstrndx].sh_offset, SEEK_SET) == 0);
    assert(fread(names, 1, sh[eh.e_shstrndx].sh_size, f) == sh[eh.e_shstrndx].sh_size);
    fclose(f);
    const char *configured = getenv("ENCBOUND_TEST_BASE"); assert(configured);
    uintptr_t base = strtoull(configured, NULL, 0);
    unsigned text_verified = 0, data_verified = 0;
    for (unsigned i = 0; i < eh.e_shnum; ++i) {
        const char *name = names+sh[i].sh_name;
        int text = !strcmp(name, ".text");
        int ro = !strcmp(name, ".encbound.appdata") || !strcmp(name, ".encbound.apprelro");
        int data = ro || !strcmp(name, ".encbound.apprw") || !strcmp(name, ".encbound.appbss") ||
            !strcmp(name, ".encbound.globalrw") || !strcmp(name, ".encbound.globalbss") ||
            !strcmp(name, ".encbound.gcaps") || !strcmp(name, ".encbound.gfix");
        if (!sh[i].sh_size || (!text && !data)) continue;
        uintptr_t start = base+sh[i].sh_addr, end = start+sh[i].sh_size;
        FILE *maps = fopen("/proc/self/maps", "r"); assert(maps);
        char line[512]; int found = 0;
        while (fgets(line, sizeof line, maps)) {
            unsigned long lo, hi; char perm[5];
            if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) == 3 && start >= lo && end <= hi) {
                assert(perm[0] == 'r' && (perm[1] == 'w') == (!text && !ro) && (perm[2] == 'x') == text);
                found = 1; break;
            }
        }
        fclose(maps); assert(found);
        if (text) ++text_verified; else ++data_verified;
    }
    assert(text_verified == 1 && data_verified);
    free(names); free(sh);
}
#define CALL(expression, expected) do { \
    sgx_status_t value = 0xffffffff; \
    sgx_status_t transport = (expression); ++calls; \
    if (transport != SGX_SUCCESS || value != (expected)) \
        fprintf(stderr, "line %d: transport=%x value=%x expected=%x\n", __LINE__, transport, value, (unsigned)(expected)); \
    assert(transport == SGX_SUCCESS && value == (expected)); \
} while (0)

static EC_KEY *new_key(void)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    assert(key && EC_KEY_generate_key(key)); return key;
}
static void public_key(EC_KEY *key, sgx_ec256_public_t *out)
{
    BIGNUM *x = BN_new(), *y = BN_new(); assert(x && y);
    assert(EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), x, y, NULL));
    assert(BN_bn2lebinpad(x, out->gx, 32) == 32 && BN_bn2lebinpad(y, out->gy, 32) == 32);
    BN_free(x); BN_free(y);
}
static void cmac(const unsigned char key[16], const void *data, size_t n, unsigned char out[16])
{
    CMAC_CTX *ctx = CMAC_CTX_new(); size_t size = 0; assert(ctx);
    assert(CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL) && CMAC_Update(ctx, data, n) && CMAC_Final(ctx, out, &size));
    assert(size == 16); CMAC_CTX_free(ctx);
}
static void derive(const unsigned char shared[32], const char *label, unsigned char out[16])
{
    unsigned char zero[16] = {0}, kdk[16], input[16] = {1};
    size_t n = strlen(label); assert(n < 10);
    memcpy(input+1, label, n); input[n+2] = 0x80;
    cmac(zero, shared, 32, kdk); cmac(kdk, input, n+4, out);
    OPENSSL_cleanse(kdk, sizeof(kdk));
}
static void message2(EC_KEY *service, const sgx_ec256_public_t *ga, sgx_ra_msg2_t *msg,
                     unsigned char sk[16], unsigned char mk[16], unsigned char vk[16])
{
    EC_KEY *peer = new_key();
    const EC_GROUP *group = EC_KEY_get0_group(peer);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *x = BN_lebin2bn(ga->gx, 32, NULL), *y = BN_lebin2bn(ga->gy, 32, NULL);
    assert(point && x && y && EC_POINT_set_affine_coordinates(group, point, x, y, NULL));
    unsigned char shared_be[32], shared[32], smk[16];
    assert(ECDH_compute_key(shared_be, 32, point, peer, NULL) == 32);
    for (unsigned i = 0; i < 32; ++i) shared[i] = shared_be[31-i];
    derive(shared, "SMK", smk); derive(shared, "SK", sk); derive(shared, "MK", mk); derive(shared, "VK", vk);
    memset(msg, 0, sizeof(*msg)); public_key(peer, &msg->g_b); msg->kdf_id = 1;
    sgx_ec256_public_t pair[2] = {msg->g_b, *ga}; unsigned char hash[32];
    assert(SHA256((const void *)pair, sizeof(pair), hash));
    ECDSA_SIG *signature = ECDSA_do_sign(hash, sizeof(hash), service); assert(signature);
    const BIGNUM *r, *s; ECDSA_SIG_get0(signature, &r, &s);
    assert(BN_bn2lebinpad(r, (void *)msg->sign_gb_ga.x, 32) == 32);
    assert(BN_bn2lebinpad(s, (void *)msg->sign_gb_ga.y, 32) == 32);
    cmac(smk, msg, offsetof(sgx_ra_msg2_t, mac), msg->mac);
    ECDSA_SIG_free(signature); BN_free(x); BN_free(y); EC_POINT_free(point); EC_KEY_free(peer);
    OPENSSL_cleanse(shared, sizeof(shared)); OPENSSL_cleanse(shared_be, sizeof(shared_be));
    OPENSSL_cleanse(smk, sizeof(smk));
}
/* Independent AES-GCM oracle, zero IV matches the selected upstream RA path. */
static void gcm(int encrypt, const uint8_t key[16], const uint8_t *in, size_t n,
                uint8_t *out, const uint8_t iv[12], const void *aad, size_t an, uint8_t tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); int count = 0, final = 0; assert(ctx);
    assert(EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, encrypt));
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL));
    assert(EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt));
    if (an) assert(EVP_CipherUpdate(ctx, NULL, &count, aad, an));
    assert(EVP_CipherUpdate(ctx, out, &count, in, n) && count == (int)n);
    if (!encrypt) assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag));
    assert(EVP_CipherFinal_ex(ctx, out+count, &final) && final == 0);
    if (encrypt) assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag));
    EVP_CIPHER_CTX_free(ctx);
}
void ocall_print_string(const char *str) { fputs(str, stdout); }
static void c16(sgx_enclave_id_t eid, sgx_ra_context_t context, const uint8_t session_sk[16], size_t sealed_len)
{
    sample_ra_att_result_msg_t incoming = {0}, outgoing = {0};
    sgx_quote_t quote = {0};
    uint8_t mr[32];
    CALL(ecall_get_mr_enclave(eid, &value, context, mr, sizeof mr), SGX_SUCCESS);
    /* The selected new-key branch compares these identities; it performs no
     * quote-signature verification. No attestation claim follows from them. */
    memcpy(quote.report_body.mr_enclave.m, mr, 32);
    memcpy(incoming.data1.payload, mr, 32);
    memcpy(incoming.data2.payload, mr, 32);
    memcpy(incoming.data3.payload, mr, 32);
    incoming.secret.payload_size = 16;
    uint8_t nonce[16], zero_iv[12] = {0};
    for (unsigned i = 0; i < 16; ++i) nonce[i] = 0x31+i;
    gcm(1, session_sk, nonce, 16, incoming.secret.payload, zero_iv, NULL, 0, incoming.secret.payload_tag);
    sp_db_item_t peer = {0};
    for (unsigned i = 0; i < 16; ++i) peer.sk_key[i] = 0xb0+i;
    void *slot = &peer;
    uint8_t *sealed_mk = calloc(1, sealed_len); assert(sealed_mk);
    uint8_t mk_sk[16] = {0}, iv[12] = {0}, mac[16] = {0}, unused_iv[12] = {0}, unused_mac[16] = {0};
    /* A benign host pointer is allowed. The slot is shallow-copied by the
     * original EDL; only its ordinary pointee supplies the outgoing key. */
#define PROC(expected) do { \
    int status = -1; \
    sgx_status_t transport = ecall_proc_ma(eid, &status, &incoming, sizeof incoming, context, \
        &quote, sizeof quote, &slot, sealed_mk, sealed_len, mk_sk, sizeof mk_sk, iv, mac, \
        0, NULL, 0, unused_iv, unused_mac, &outgoing, sizeof outgoing, NULL, 0); ++calls; \
    if (transport || status != (expected)) fprintf(stderr, "C16 line %d: transport=%x status=%d expected=%d\n", __LINE__, transport, status, expected); \
    assert(transport == SGX_SUCCESS && status == (expected)); \
} while (0)
    incoming.data2.payload[0] ^= 1;
    PROC(3); /* identity mismatch, then recover using the same RA session */
    incoming.data2.payload[0] ^= 1;
    incoming.secret.payload_tag[0] ^= 1;
    PROC(4); /* invalid GCM tag; the C16 sink must remain unreachable */
    incoming.secret.payload_tag[0] ^= 1;
    memset(sealed_mk, 0, sealed_len); memset(mk_sk, 0, sizeof mk_sk);
    PROC(0);
    assert(outgoing.secret.payload_size == 16 && outgoing.data1.payload_size == 16);
    uint8_t plain[32];
    gcm(0, peer.sk_key, outgoing.secret.payload, 16, plain, zero_iv, NULL, 0, outgoing.secret.payload_tag);
    assert(!memcmp(plain, nonce, 16)); ++verified_keys;
    gcm(0, peer.sk_key, outgoing.data1.payload, 16, plain, zero_iv, NULL, 0, outgoing.data1.payload_tag);
    /* The second output is the freshly generated server key. It must also
     * decrypt application-generated traffic associated with that sealed key. */
    uint8_t generated_key[16]; memcpy(generated_key, plain, 16);
    CALL(ecall_decrypt(eid, &value, sealed_mk, sealed_len, plain, 16, mk_sk, iv, mac, NULL, 0), SGX_SUCCESS);
    assert(!memcmp(plain, generated_key, 16)); ++verified_keys;
    /* A second fresh new-key branch in the same session confirms gate/session
     * reuse; independently verify its nonce ciphertext again. */
    memset(sealed_mk, 0, sealed_len); memset(mk_sk, 0, sizeof mk_sk);
    PROC(0);
    gcm(0, peer.sk_key, outgoing.secret.payload, 16, plain, zero_iv, NULL, 0, outgoing.secret.payload_tag);
    assert(!memcmp(plain, nonce, 16)); ++verified_keys;
    OPENSSL_cleanse(generated_key, sizeof generated_key);
    free(sealed_mk);
#undef PROC
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    sgx_enclave_id_t eid;
    assert(sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL) == SGX_SUCCESS);
    permissions(argv[1]);
    size_t sealed_len = 0;
    assert(ecall_get_sealed_data_len(eid, &sealed_len, 0, 16) == SGX_SUCCESS); ++calls;
    assert(sealed_len > 16 && sealed_len < 2048);
    for (unsigned iteration = 0; iteration < 3; ++iteration) {
        EC_KEY *service = new_key(); sgx_ec256_public_t pub, ga;
        public_key(service, &pub);
        sgx_ra_context_t context;
        CALL(enclave_init_ra(eid, &value, 1, &context, &pub), SGX_ERROR_FEATURE_NOT_SUPPORTED);
        CALL(enclave_init_ra(eid, &value, 0, &context, &pub), SGX_SUCCESS);
        uint8_t *sealed_sk = calloc(1, sealed_len); assert(sealed_sk);
        CALL(ecall_get_ra_dh_key(eid, &value, context, sealed_sk, sealed_len), SGX_ERROR_INVALID_STATE);
        CALL(sgx_ra_get_ga(eid, &value, context, &ga), SGX_SUCCESS);
        sgx_target_info_t target;
        assert(sgx_get_target_info(eid, &target) == SGX_SUCCESS);
        sgx_ra_msg2_t msg; unsigned char sk[16], mk[16], vk[16];
        message2(service, &ga, &msg, sk, mk, vk);
        sgx_report_t report; sgx_quote_nonce_t nonce;
        msg.sign_gb_ga.x[0] ^= 1;
        CALL(sgx_ra_proc_msg2_trusted(eid, &value, context, &msg, &target, &report, &nonce), SGX_ERROR_INVALID_SIGNATURE);
        msg.sign_gb_ga.x[0] ^= 1; msg.mac[0] ^= 1;
        CALL(sgx_ra_proc_msg2_trusted(eid, &value, context, &msg, &target, &report, &nonce), SGX_ERROR_MAC_MISMATCH);
        msg.mac[0] ^= 1;
        CALL(sgx_ra_proc_msg2_trusted(eid, &value, context, &msg, &target, &report, &nonce), SGX_SUCCESS);
        unsigned char report_input[144], report_hash[32];
        memcpy(report_input, &ga, 64); memcpy(report_input+64, &msg.g_b, 64); memcpy(report_input+128, vk, 16);
        assert(SHA256(report_input, sizeof report_input, report_hash));
        assert(!memcmp(report.body.report_data.d, report_hash, 32));
        for (unsigned i = 32; i < 64; ++i) assert(report.body.report_data.d[i] == 0);
        uint8_t message[37], plaintext[37], ciphertext[37], iv[12] = {0}, tag[16];
        memset(message, 0x80+iteration, sizeof message);
        uint8_t expected_tag[16]; cmac(mk, message, sizeof message, expected_tag);
        expected_tag[0] ^= 1;
        CALL(verify_att_result_mac(eid, &value, context, message, sizeof message, expected_tag, 16), SGX_ERROR_MAC_MISMATCH);
        expected_tag[0] ^= 1;
        CALL(verify_att_result_mac(eid, &value, context, message, sizeof message, expected_tag, 16), SGX_SUCCESS);
        CALL(ecall_get_ra_dh_key(eid, &value, context, sealed_sk, sealed_len), SGX_SUCCESS);
        size_t text_len;
        assert(ecall_get_encrypt_txt_len(eid, &text_len, sealed_sk, sealed_len) == SGX_SUCCESS && text_len == 16); ++calls;
        size_t aad_len;
        assert(ecall_get_add_mac_len(eid, &aad_len, sealed_sk, sealed_len) == SGX_SUCCESS && aad_len == 0); ++calls;
        uint8_t aad[3] = {1, 3, 7};
        CALL(ecall_encrypt(eid, &value, sealed_sk, sealed_len, message, sizeof message, ciphertext, iv, tag, aad, sizeof aad), SGX_SUCCESS);
        gcm(0, sk, ciphertext, sizeof ciphertext, plaintext, iv, aad, sizeof aad, tag);
        assert(!memcmp(plaintext, message, sizeof message)); ++verified_keys;
        gcm(1, sk, message, sizeof message, ciphertext, iv, NULL, 0, tag);
        CALL(ecall_decrypt(eid, &value, sealed_sk, sealed_len, plaintext, sizeof plaintext, ciphertext, iv, tag, NULL, 0), SGX_SUCCESS);
        assert(!memcmp(plaintext, message, sizeof message)); ++verified_keys;
        tag[0] ^= 1;
        CALL(ecall_decrypt(eid, &value, sealed_sk, sealed_len, plaintext, sizeof plaintext, ciphertext, iv, tag, NULL, 0), SGX_ERROR_MAC_MISMATCH);
        tag[0] ^= 1;
        uint8_t *generated = calloc(1, sealed_len); assert(generated);
        CALL(ecall_generate_key(eid, &value, 16, generated, sealed_len), SGX_SUCCESS);
        int comparison = -1;
        assert(ecall_sealed_cmp(eid, &comparison, generated, sealed_len, generated, sealed_len) == SGX_SUCCESS && comparison == 0); ++calls;
        uint8_t transported[16];
        CALL(ecall_transport_secret(eid, &value, sealed_sk, sealed_len, generated, sealed_len, transported, 16, iv, tag, NULL, 0), SGX_SUCCESS);
        gcm(0, sk, transported, 16, plaintext, iv, NULL, 0, tag);
        /* Recover the generated key independently under the negotiated SK,
         * then use it as the selected equal-length store/get workflow key. */
        CALL(ecall_provision_kek(eid, &value, sealed_sk, sealed_len, transported, 16, iv, tag, generated, sealed_len, NULL, 0), SGX_SUCCESS);
        uint8_t raw_sk[16]; memcpy(raw_sk, plaintext, 16);
        uint8_t kek_enc_sk[16], sk_iv[12] = {0}, sk_tag[16];
        CALL(ecall_encrypt(eid, &value, generated, sealed_len, raw_sk, 16, kek_enc_sk, sk_iv, sk_tag, NULL, 0), SGX_SUCCESS);
        uint8_t secret[16], sk_cipher[16], kek_cipher[16], recovered[16];
        memset(secret, 0xc0+iteration, 16);
        gcm(1, raw_sk, secret, 16, sk_cipher, iv, NULL, 0, tag);
        CALL(ecall_store_secret(eid, &value, kek_enc_sk, 16, sk_iv, sk_tag, generated, sealed_len,
             sk_cipher, 16, kek_cipher, 16, iv, tag, NULL, 0), SGX_SUCCESS);
        CALL(ecall_decrypt(eid, &value, generated, sealed_len, recovered, 16, kek_cipher, iv, tag, NULL, 0), SGX_SUCCESS);
        assert(!memcmp(recovered, secret, 16)); ++verified_keys;
        CALL(ecall_get_secret(eid, &value, kek_enc_sk, 16, sk_iv, sk_tag, generated, sealed_len,
             kek_cipher, 16, sk_cipher, 16, iv, tag, NULL, 0), SGX_SUCCESS);
        gcm(0, raw_sk, sk_cipher, 16, recovered, iv, NULL, 0, tag);
        assert(!memcmp(recovered, secret, 16)); ++verified_keys;
        gcm(1, sk, secret, 16, sk_cipher, iv, NULL, 0, tag);
        CALL(server_get_project_id(eid, &value, context, sk_cipher, 16, tag, recovered, 16), SGX_SUCCESS);
        assert(!memcmp(recovered, secret, 16)); ++verified_keys;
        CALL(client_put_secret_data(eid, &value, context, sk_cipher, 16, tag, generated, sealed_len), SGX_SUCCESS);
        CALL(ecall_transport_secret(eid, &value, sealed_sk, sealed_len, generated, sealed_len, transported, 16, iv, tag, NULL, 0), SGX_SUCCESS);
        gcm(0, sk, transported, 16, recovered, iv, NULL, 0, tag);
        assert(!memcmp(recovered, secret, 16)); ++verified_keys;
        c16(eid, context, sk, sealed_len);
        CALL(enclave_ra_close(eid, &value, context), SGX_SUCCESS);
        CALL(ecall_get_ra_dh_key(eid, &value, context, sealed_sk, sealed_len), SGX_ERROR_INVALID_PARAMETER);
        free(generated); free(sealed_sk); EC_KEY_free(service);
        OPENSSL_cleanse(sk, sizeof sk); OPENSSL_cleanse(mk, sizeof mk);
    }
    assert(calls == 103 && verified_keys == 27);
    assert(sgx_destroy_enclave(eid) == SGX_SUCCESS);
    printf("SGX-KMS C16 BENIGN SIM PASS calls=%u independent_checks=%u valid_msg2=3 c16_success=6 c16_identity_reject=3 c16_tag_reject=3\n", calls, verified_keys);
    return 0;
}
