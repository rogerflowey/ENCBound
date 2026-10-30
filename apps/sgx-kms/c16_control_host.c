/* C16 hostile-pointer protection control for the pinned SGX-KMS enclave.
 *
 * The unchanged EDL declares:
 *   public int ecall_proc_ma(..., [in] void **c_p_net_ctxt, ...);
 *
 * `[in] void **` copies one pointer value (Intel shallow transport).  The
 * unchanged body later does:
 *   sp_db = (sp_db_item_t *)*c_p_net_ctxt;
 *   server_put_secret_data(..., (uint8_t *)&sp_db->sk_key, ...);
 * so the host chooses the 16-byte key that encrypts the two outgoing C16
 * payloads.  This probe compares a benign host key with two raw enclave
 * targets at that checked consumption site:
 *
 *   control     host sp_db_item_t with a known key (allowed in every profile)
 *   cd-app      the image's own zero-initialized protected global g_secret
 *   cd-trusted  the pinned SDK RA database item's sk_key (session SK)
 *
 * BASELINE has no pointer instrumentation, so it reads the chosen key and the
 * host verifies both outgoing ciphertexts with that same known key.  The
 * protected profiles should reject the raw enclave key range in the checked
 * GCM adapter before the SDK reads or encrypts anything.
 *
 * SDK SIM only.  The host reads the image's own .symtab and, for cd-trusted,
 * the simulated process's mapped g_ra_db vector.  That is a test premise, not
 * a production address leak.  No hardware, secret-extraction or full SGX-KMS
 * deployment claim is made.
 */
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
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#define SAMPLE_ECP_KEY_SIZE 32
#include "host_types.h"

#define SP_SK_OFFSET offsetof(sp_db_item_t, sk_key)
/* Pinned SDK 2.26 tkey_exchange/tkey_exchange.cpp: ra_db_item_t is packed and
 * sk_key follows mk_key.  The runner compiles the layout check below; these
 * constants are asserted again here so a changed SDK pin fails visibly. */
#define RA_DB_ITEM_SK_OFFSET 512u
#define RA_DB_ITEM_SIZE 1088u

struct simple_vector { uint32_t size, capacity; void **data; };

__attribute__((noinline)) void kms_c16_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

void ocall_print_string(const char *str) { fputs(str, stdout); }

static int mapped_rw(uintptr_t start, size_t len)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long lo, hi; char perm[5];
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) == 3 &&
            start >= lo && (uintptr_t)len <= hi - start &&
            perm[0] == 'r' && perm[1] == 'w') {
            found = 1;
            break;
        }
    }
    fclose(maps);
    return found;
}

static int find_symbol(const char *image, const char *wanted, uint64_t *value)
{
    FILE *f = fopen(image, "rb");
    if (!f) return 0;
    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof eh, f) != sizeof eh || eh.e_shnum == 0) {
        fclose(f); return 0;
    }
    Elf64_Shdr *sh = calloc(eh.e_shnum, sizeof(*sh));
    if (!sh) { fclose(f); return 0; }
    if (fseek(f, eh.e_shoff, SEEK_SET) != 0 ||
        fread(sh, sizeof(*sh), eh.e_shnum, f) != eh.e_shnum) {
        free(sh); fclose(f); return 0;
    }
    int found = 0;
    for (unsigned i = 0; i < eh.e_shnum && !found; ++i) {
        if (sh[i].sh_type != SHT_SYMTAB || sh[i].sh_entsize != sizeof(Elf64_Sym) ||
            sh[i].sh_link >= eh.e_shnum)
            continue;
        Elf64_Sym *syms = malloc(sh[i].sh_size);
        Elf64_Shdr *str = &sh[sh[i].sh_link];
        char *names = malloc(str->sh_size);
        if (!syms || !names) { free(syms); free(names); break; }
        if (fseek(f, sh[i].sh_offset, SEEK_SET) == 0 &&
            fread(syms, 1, sh[i].sh_size, f) == sh[i].sh_size &&
            fseek(f, str->sh_offset, SEEK_SET) == 0 &&
            fread(names, 1, str->sh_size, f) == str->sh_size) {
            size_t count = sh[i].sh_size / sizeof(*syms);
            for (size_t j = 0; j < count; ++j) {
                if (syms[j].st_name < str->sh_size &&
                    !strcmp(names + syms[j].st_name, wanted)) {
                    *value = syms[j].st_value;
                    found = 1;
                    break;
                }
            }
        }
        free(syms); free(names);
    }
    free(sh); fclose(f);
    return found;
}

static EC_KEY *new_key(void)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    assert(key && EC_KEY_generate_key(key)); return key;
}
static void public_key(EC_KEY *key, sgx_ec256_public_t *out)
{
    BIGNUM *x = BN_new(), *y = BN_new(); assert(x && y);
    assert(EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key),
        EC_KEY_get0_public_key(key), x, y, NULL));
    assert(BN_bn2lebinpad(x, out->gx, 32) == 32);
    assert(BN_bn2lebinpad(y, out->gy, 32) == 32);
    BN_free(x); BN_free(y);
}
static void cmac(const unsigned char key[16], const void *data, size_t n,
                 unsigned char out[16])
{
    CMAC_CTX *ctx = CMAC_CTX_new(); size_t size = 0; assert(ctx);
    assert(CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL));
    assert(CMAC_Update(ctx, data, n) && CMAC_Final(ctx, out, &size));
    assert(size == 16); CMAC_CTX_free(ctx);
}
static void derive(const unsigned char shared[32], const char *label,
                   unsigned char out[16])
{
    unsigned char zero[16] = {0}, kdk[16], input[16] = {1};
    size_t n = strlen(label); assert(n < 10);
    memcpy(input+1, label, n); input[n+2] = 0x80;
    cmac(zero, shared, 32, kdk); cmac(kdk, input, n+4, out);
    OPENSSL_cleanse(kdk, sizeof(kdk));
}
static void message2(EC_KEY *service, const sgx_ec256_public_t *ga,
                     sgx_ra_msg2_t *msg, unsigned char sk[16],
                     unsigned char mk[16], unsigned char vk[16])
{
    EC_KEY *peer = new_key();
    const EC_GROUP *group = EC_KEY_get0_group(peer);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *x = BN_lebin2bn(ga->gx, 32, NULL);
    BIGNUM *y = BN_lebin2bn(ga->gy, 32, NULL);
    assert(point && x && y &&
           EC_POINT_set_affine_coordinates(group, point, x, y, NULL));
    unsigned char shared_be[32], shared[32], smk[16];
    assert(ECDH_compute_key(shared_be, 32, point, peer, NULL) == 32);
    for (unsigned i = 0; i < 32; ++i) shared[i] = shared_be[31-i];
    derive(shared, "SMK", smk); derive(shared, "SK", sk);
    derive(shared, "MK", mk); derive(shared, "VK", vk);
    memset(msg, 0, sizeof(*msg)); public_key(peer, &msg->g_b); msg->kdf_id = 1;
    sgx_ec256_public_t pair[2] = {msg->g_b, *ga}; unsigned char hash[32];
    assert(SHA256((const void *)pair, sizeof(pair), hash));
    ECDSA_SIG *signature = ECDSA_do_sign(hash, sizeof(hash), service);
    assert(signature);
    const BIGNUM *r, *s; ECDSA_SIG_get0(signature, &r, &s);
    assert(BN_bn2lebinpad(r, (void *)msg->sign_gb_ga.x, 32) == 32);
    assert(BN_bn2lebinpad(s, (void *)msg->sign_gb_ga.y, 32) == 32);
    cmac(smk, msg, offsetof(sgx_ra_msg2_t, mac), msg->mac);
    ECDSA_SIG_free(signature); BN_free(x); BN_free(y);
    EC_POINT_free(point); EC_KEY_free(peer);
    OPENSSL_cleanse(shared, sizeof shared);
    OPENSSL_cleanse(shared_be, sizeof shared_be);
    OPENSSL_cleanse(smk, sizeof smk);
}
static void gcm(int encrypt, const uint8_t key[16], const uint8_t *in, size_t n,
                uint8_t *out, const uint8_t iv[12], const void *aad,
                size_t an, uint8_t tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); int count = 0, final = 0;
    assert(ctx);
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

static uint64_t base_address(void)
{
    const char *configured = getenv("ENCBOUND_TEST_BASE");
    return configured ? strtoull(configured, NULL, 0) : 0x40000000ull;
}

static uintptr_t key_address(const char *image, uint64_t base, int app_target,
                             sgx_ra_context_t context)
{
    uint64_t symbol = 0;
    if (app_target) {
        assert(find_symbol(image, "g_secret", &symbol));
        return (uintptr_t)(base + symbol);
    }
    assert(find_symbol(image, "_ZL7g_ra_db", &symbol));
    struct simple_vector *vector = (struct simple_vector *)(uintptr_t)(base + symbol);
    assert(mapped_rw((uintptr_t)vector, sizeof *vector));
    assert(vector->size > context && vector->data);
    assert(mapped_rw((uintptr_t)vector->data, (context+1)*sizeof(void *)));
    void *item = vector->data[context];
    assert(item);
    assert(mapped_rw((uintptr_t)item, RA_DB_ITEM_SIZE));
    return (uintptr_t)item + RA_DB_ITEM_SK_OFFSET;
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    const char *image = argv[1];
    int control = !strcmp(argv[2], "control");
    int app_target = !strcmp(argv[2], "cd-app");
    int trusted_target = !strcmp(argv[2], "cd-trusted");
    if (!control && !app_target && !trusted_target) {
        fprintf(stderr, "usage: %s <enclave.signed.so> "
                "<control|cd-app|cd-trusted>\n", argv[0]);
        return 2;
    }
    uint64_t base = base_address();
    sgx_enclave_id_t eid = 0;
    sgx_status_t created = sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL,
                                              &eid, NULL);
    if (created) {
        fprintf(stderr, "create=%#x\n", (unsigned)created);
        return 3;
    }

    EC_KEY *service = new_key();
    sgx_ec256_public_t pub, ga;
    public_key(service, &pub);
    sgx_ra_context_t context;
    sgx_status_t value = SGX_SUCCESS;
    assert(enclave_init_ra(eid, &value, 0, &context, &pub) == SGX_SUCCESS);
    assert(value == SGX_SUCCESS);
    assert(sgx_ra_get_ga(eid, &value, context, &ga) == SGX_SUCCESS);
    assert(value == SGX_SUCCESS);
    sgx_target_info_t target_info;
    assert(sgx_get_target_info(eid, &target_info) == SGX_SUCCESS);
    sgx_ra_msg2_t msg;
    unsigned char sk[16], mk[16], vk[16];
    message2(service, &ga, &msg, sk, mk, vk);
    sgx_report_t report; sgx_quote_nonce_t nonce;
    assert(sgx_ra_proc_msg2_trusted(eid, &value, context, &msg, &target_info,
                                    &report, &nonce) == SGX_SUCCESS);
    assert(value == SGX_SUCCESS);

    sample_ra_att_result_msg_t incoming = {0}, outgoing = {0};
    sgx_quote_t quote = {0};
    uint8_t mr[32];
    assert(ecall_get_mr_enclave(eid, &value, context, mr, sizeof mr) == SGX_SUCCESS);
    assert(value == SGX_SUCCESS);
    memcpy(quote.report_body.mr_enclave.m, mr, 32);
    memcpy(incoming.data1.payload, mr, 32);
    memcpy(incoming.data2.payload, mr, 32);
    memcpy(incoming.data3.payload, mr, 32);
    incoming.secret.payload_size = 16;
    uint8_t nonce_plain[16], zero_iv[12] = {0};
    for (unsigned i = 0; i < 16; ++i) nonce_plain[i] = 0x31+i;
    gcm(1, sk, nonce_plain, 16, incoming.secret.payload, zero_iv, NULL, 0,
        incoming.secret.payload_tag);

    sp_db_item_t peer = {0};
    for (unsigned i = 0; i < 16; ++i) peer.sk_key[i] = 0xb0+i;
    uint8_t expected[16] = {0};
    uintptr_t target_key = 0;
    const char *source = "host";
    void *slot = NULL;
    if (control) {
        slot = &peer;
        target_key = (uintptr_t)&peer.sk_key;
        memcpy(expected, peer.sk_key, sizeof expected);
    } else {
        target_key = key_address(image, base, app_target, context);
        if (app_target) {
            source = "g_secret";
            /* g_secret is zero-initialized application BSS. */
            memset(expected, 0, sizeof expected);
        } else {
            source = "ra_db.sk_key";
            memcpy(expected, sk, sizeof expected);
        }
        assert(mapped_rw(target_key, 16));
        uintptr_t target = target_key - SP_SK_OFFSET;
        assert(mapped_rw(target, SP_SK_OFFSET + 16));
        slot = (void *)target;
    }

    size_t sealed_len = 0;
    assert(ecall_get_sealed_data_len(eid, &sealed_len, 0, 16) == SGX_SUCCESS);
    assert(sealed_len > 16 && sealed_len < 2048);
    uint8_t *sealed_mk = calloc(1, sealed_len); assert(sealed_mk);
    uint8_t mk_sk[16] = {0}, iv[12] = {0}, mac[16] = {0};
    uint8_t unused_iv[12] = {0}, unused_mac[16] = {0};
    if (!control) {
        printf("{\"mode\":\"%s\",\"stage\":\"target\",\"source\":\"%s\","
               "\"target\":\"%#lx\",\"key\":\"%#lx\"}\n", argv[2], source,
               (unsigned long)(uintptr_t)slot, (unsigned long)target_key);
        fflush(stdout);
    }
    kms_c16_ready();
    int status = -1;
    sgx_status_t transport = ecall_proc_ma(eid, &status, &incoming,
        sizeof incoming, context, &quote, sizeof quote, &slot, sealed_mk,
        sealed_len, mk_sk, sizeof mk_sk, iv, mac, 0, NULL, 0, unused_iv,
        unused_mac, &outgoing, sizeof outgoing, NULL, 0);
    if (transport != SGX_SUCCESS || status != 0) {
        fprintf(stderr, "%s C16 failed transport=%#x status=%d\n", argv[2],
                (unsigned)transport, status);
        return 4;
    }
    assert(outgoing.secret.payload_size == 16);
    assert(outgoing.data1.payload_size == 16);
    uint8_t plain[32], generated[16];
    gcm(0, expected, outgoing.secret.payload, 16, plain, zero_iv, NULL, 0,
        outgoing.secret.payload_tag);
    int nonce_ok = !memcmp(plain, nonce_plain, 16);
    gcm(0, expected, outgoing.data1.payload, 16, generated, zero_iv, NULL, 0,
        outgoing.data1.payload_tag);
    printf("{\"mode\":\"%s\",\"status\":0,\"source\":\"%s\","
           "\"target\":\"%#lx\",\"key\":\"%#lx\",\"nonce_verified\":%s,"
           "\"server_key_ciphertext\":\"%s\"}\n",
           argv[2], source, (unsigned long)(uintptr_t)slot,
           (unsigned long)target_key, nonce_ok ? "true" : "false",
           "decrypted");
    OPENSSL_cleanse(expected, sizeof expected);
    OPENSSL_cleanse(sk, sizeof sk); OPENSSL_cleanse(mk, sizeof mk);
    free(sealed_mk); EC_KEY_free(service);
    return nonce_ok ? 0 : 5;
}
