/* Independent OpenSSL peer for real SDK RA message-2 processing in SIM.
 * No IAS, quote production, hardware attestation or SGX-KMS C16 claim. */
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
#include "probe_u.h"

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
int main(int argc, char **argv)
{
    assert(argc == 2);
    sgx_enclave_id_t eid;
    assert(sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL) == SGX_SUCCESS);
    permissions(argv[1]);
    for (unsigned iteration = 0; iteration < 3; ++iteration) {
        EC_KEY *service = new_key(); sgx_ec256_public_t pub, ga;
        public_key(service, &pub);
        sgx_ra_context_t context; sgx_target_info_t target;
        CALL(session_start(eid, &value, &pub, &context, &target), SGX_SUCCESS);
        sgx_ra_key_128_t key;
        CALL(session_key(eid, &value, context, SGX_RA_KEY_SK, &key), SGX_ERROR_INVALID_STATE);
        CALL(sgx_ra_get_ga(eid, &value, context, &ga), SGX_SUCCESS);
        CALL(sgx_ra_get_ga(eid, &value, context, &ga), SGX_ERROR_INVALID_STATE);
        /* The SDK initializes output even on a service error; get a fresh
         * context for the real peer rather than reusing that overwritten ga. */
        CALL(session_close(eid, &value, context), SGX_SUCCESS);
        CALL(session_start(eid, &value, &pub, &context, &target), SGX_SUCCESS);
        CALL(sgx_ra_get_ga(eid, &value, context, &ga), SGX_SUCCESS);
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
        assert(SHA256(report_input, sizeof(report_input), report_hash));
        assert(!memcmp(report.body.report_data.d, report_hash, 32));
        for (unsigned i = 32; i < 64; ++i) assert(report.body.report_data.d[i] == 0);
        CALL(session_key(eid, &value, context, SGX_RA_KEY_SK, &key), SGX_SUCCESS);
        assert(!memcmp(key, sk, 16)); ++verified_keys;
        CALL(session_key(eid, &value, context, SGX_RA_KEY_MK, &key), SGX_SUCCESS);
        assert(!memcmp(key, mk, 16)); ++verified_keys;
        uint32_t quote_size = 16, msg3_size = sizeof(sgx_ra_msg3_t)+quote_size;
        /* A raw enclave address must fail the SDK's user_check validation,
         * before report verification or a write to that address. */
        uintptr_t base = strtoull(getenv("ENCBOUND_TEST_BASE"), NULL, 0);
        CALL(sgx_ra_get_msg3_trusted(eid, &value, context, quote_size, &report, (void *)base, msg3_size), SGX_ERROR_INVALID_PARAMETER);
        CALL(session_close(eid, &value, context), SGX_SUCCESS);
        CALL(sgx_ra_get_ga(eid, &value, context, &ga), SGX_ERROR_INVALID_PARAMETER);
        EC_KEY_free(service);
    }
    uint32_t count = 0;
    assert(session_count(eid, &count) == SGX_SUCCESS && count == 6); ++calls;
    assert(sgx_destroy_enclave(eid) == SGX_SUCCESS);
    printf("SDK RA SIM PASS calls=%u verified_session_keys=%u valid_msg2=3\n", calls, verified_keys);
    return 0;
}
