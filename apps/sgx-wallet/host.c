/*
 * ENCBound restart - sgx-wallet candidate host harness (step 0).
 *
 * Minimal host for the pinned asonnino/sgx-wallet enclave. It provides the
 * four OCALLs with an in-memory sealed-wallet backend and drives either the
 * benign create/show/change cycle or a controlled show with a caller-supplied
 * (possibly too small) output length.
 *
 * This is an evaluation harness, not an ENCBound-integrated application.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_urts.h"
#include "enclave_u.h"
#include "wallet.h"
#include "enclave.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define SEALED_CAP (1u << 20)

static uint8_t g_sealed[SEALED_CAP];
static size_t g_sealed_len;

void ocall_debug_print(const char *str)
{
    printf("ENCLAVE DEBUG: %s\n", str);
}

int ocall_save_wallet(const uint8_t *sealed_data, size_t sealed_size)
{
    if (sealed_size > sizeof(g_sealed)) {
        return 1;
    }
    memcpy(g_sealed, sealed_data, sealed_size);
    g_sealed_len = sealed_size;
    return 0;
}

int ocall_load_wallet(uint8_t *sealed_data, size_t sealed_size)
{
    if (g_sealed_len == 0 || sealed_size < g_sealed_len) {
        return 1;
    }
    memcpy(sealed_data, g_sealed, g_sealed_len);
    return 0;
}

int ocall_is_wallet(void)
{
    return g_sealed_len != 0;
}

static int do_create(sgx_enclave_id_t eid, const char *password)
{
    sgx_status_t status;
    int ret = -1;
    status = ecall_create_wallet(eid, &ret, password);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "FAIL: create transport 0x%04x\n", status);
        return 1;
    }
    if (ret != RET_SUCCESS) {
        fprintf(stderr, "FAIL: create returned %d\n", ret);
        return 1;
    }
    return 0;
}

static int do_change(sgx_enclave_id_t eid, const char *old_pw,
                     const char *new_pw)
{
    sgx_status_t status;
    int ret = -1;
    status = ecall_change_master_password(eid, &ret, old_pw, new_pw);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "FAIL: change transport 0x%04x\n", status);
        return 1;
    }
    if (ret != RET_SUCCESS) {
        fprintf(stderr, "FAIL: change returned %d\n", ret);
        return 1;
    }
    return 0;
}

static int do_show(sgx_enclave_id_t eid, const char *password, void *buffer,
                   size_t wallet_size, int *ret_out)
{
    return ecall_show_wallet(eid, ret_out, password, (wallet_t *)buffer,
                             wallet_size);
}

static int run_benign(sgx_enclave_id_t eid)
{
    static wallet_t wallet;
    sgx_status_t status;
    int ret = -1;

    if (do_create(eid, "password123") != 0) {
        return 1;
    }

    memset(&wallet, 0, sizeof(wallet));
    status = do_show(eid, "password123", &wallet, sizeof(wallet), &ret);
    if (status != SGX_SUCCESS || ret != RET_SUCCESS) {
        fprintf(stderr, "FAIL: benign show status=0x%04x ret=%d\n", status,
                ret);
        return 1;
    }
    if (wallet.size != 0 ||
        strcmp(wallet.master_password, "password123") != 0) {
        fprintf(stderr, "FAIL: wallet content mismatch after create\n");
        return 1;
    }

    if (do_change(eid, "password123", "password456") != 0) {
        return 1;
    }

    memset(&wallet, 0, sizeof(wallet));
    status = do_show(eid, "password456", &wallet, sizeof(wallet), &ret);
    if (status != SGX_SUCCESS || ret != RET_SUCCESS ||
        strcmp(wallet.master_password, "password456") != 0) {
        fprintf(stderr, "FAIL: show after change status=0x%04x ret=%d\n",
                status, ret);
        return 1;
    }

    printf("BENIGN PASS (wallet_t=%zu bytes)\n", sizeof(wallet_t));
    return 0;
}

static int run_overflow(sgx_enclave_id_t eid, size_t wallet_size)
{
    sgx_status_t status;
    int ret = -1;
    uint8_t *buffer;

    if (do_create(eid, "password123") != 0) {
        return 1;
    }

    /* The caller controls wallet_size; allocate exactly that. */
    buffer = (uint8_t *)malloc(wallet_size == 0 ? 1 : wallet_size);
    if (buffer == NULL) {
        return 1;
    }
    memset(buffer, 0, wallet_size);
    printf("overflow probe: sizeof(wallet_t)=%zu wallet_size=%zu\n",
           sizeof(wallet_t), wallet_size);
    status = do_show(eid, "password123", buffer, wallet_size, &ret);
    printf("overflow probe returned: transport=0x%04x ret=%d\n", status, ret);
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    sgx_enclave_id_t eid = 0;
    sgx_status_t status;
    size_t wallet_size = 16;
    int overflow = 0;
    int i;
    int rc;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--overflow") == 0) {
            overflow = 1;
        } else if (strcmp(argv[i], "--wallet-size") == 0 && i + 1 < argc) {
            wallet_size = (size_t)strtoul(argv[++i], NULL, 0);
        }
    }

    status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, NULL, NULL, &eid,
                                NULL);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "FAIL: sgx_create_enclave 0x%04x\n", status);
        return 1;
    }

    rc = overflow ? run_overflow(eid, wallet_size) : run_benign(eid);

    sgx_destroy_enclave(eid);
    return rc;
}
