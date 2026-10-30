/*
 * ENCBound restart - sgx-wallet sequential session host
 * (docs/legacy/steps/09-original-api-and-sessions.md).
 *
 * Drives the pinned application through its original public ECALLs on one
 * enclave: create, show, change, add, remove and further calls, then destroys
 * the enclave at session end. It owns the four OCALLs with an in-memory sealed
 * wallet backend.
 *
 * This is the dedicated evaluation harness; the pinned upstream host/test
 * sources (app/app.cpp, app/test.cpp) exercise the same public ECALLs with
 * their call sites unchanged in a separate compatibility row (host-upstream).
 * Host C++ is ordinary untrusted host code.
 *
 * The generated trusted adapters own admission, initialize-once, protected
 * marshaling and cleanup; this host only observes transport and application
 * results. See docs/legacy/steps/09 and docs/legacy/contracts/request-path.md.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "enclave_u.h"
#include "wallet.h"
#include "enclave.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define SEALED_CAP (1u << 20)

static uint8_t g_sealed[SEALED_CAP];
static size_t g_sealed_len;
enum reply_mode { REPLY_OK, SAVE_FAIL, LOAD_FAIL, BAD_BLOB_LENGTH, BAD_BLOB_MAC, REENTER };
static enum reply_mode g_reply_mode;
static sgx_enclave_id_t g_active_eid;
static int g_nested_attempted;
static sgx_status_t g_nested_status;

/***************************************************
 * OCALLs (in-memory sealed-wallet backend)
 ***************************************************/
void ocall_debug_print(const char *str)
{
    printf("ENCLAVE DEBUG: %s\n", str);
}

int ocall_save_wallet(const uint8_t *sealed_data, size_t sealed_size)
{
    if (g_reply_mode == SAVE_FAIL || sealed_size > sizeof(g_sealed)) {
        return 1;
    }
    memcpy(g_sealed, sealed_data, sealed_size);
    g_sealed_len = sealed_size;
    return 0;
}

int ocall_load_wallet(uint8_t *sealed_data, size_t sealed_size)
{
    if (g_reply_mode == REENTER) {
        int app = 0;
        static wallet_t nested_out;
        g_nested_attempted = 1;
        g_nested_status = ecall_show_wallet(g_active_eid, &app,
                                            "password123", &nested_out,
                                            sizeof(nested_out));
    }
    if (g_reply_mode == LOAD_FAIL || g_sealed_len == 0 ||
        sealed_size < g_sealed_len) {
        return 1;
    }
    memset(sealed_data, 0, sealed_size);
    memcpy(sealed_data, g_sealed, g_sealed_len);
    if (g_reply_mode == BAD_BLOB_LENGTH) {
        ((sgx_sealed_data_t *)sealed_data)->aes_data.payload_size = UINT32_MAX;
    }
    if (g_reply_mode == BAD_BLOB_MAC) {
        ((sgx_sealed_data_t *)sealed_data)->aes_data.payload_tag[0] ^= 1;
    }
    return 0;
}

int ocall_is_wallet(void)
{
    return g_sealed_len != 0;
}

/***************************************************
 * ECALL helpers
 ***************************************************/
static sgx_enclave_id_t create_enclave(void)
{
    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
                                             NULL, NULL, &eid, NULL);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "FAIL: sgx_create_enclave 0x%04x\n", status);
        return 0;
    }
    g_active_eid = eid;
    return eid;
}

static sgx_status_t call_create(sgx_enclave_id_t eid, const char *pw, int *app)
{
    *app = -1;
    return ecall_create_wallet(eid, app, pw);
}

static sgx_status_t call_show(sgx_enclave_id_t eid, const char *pw,
                              wallet_t *wallet, size_t wallet_size, int *app)
{
    *app = -1;
    return ecall_show_wallet(eid, app, pw, wallet, wallet_size);
}

static sgx_status_t call_change(sgx_enclave_id_t eid, const char *old_pw,
                                const char *new_pw, int *app)
{
    *app = -1;
    return ecall_change_master_password(eid, app, old_pw, new_pw);
}

static sgx_status_t call_add(sgx_enclave_id_t eid, const char *pw,
                             const item_t *item, size_t item_size, int *app)
{
    *app = -1;
    return ecall_add_item(eid, app, pw, item, item_size);
}

static sgx_status_t call_remove(sgx_enclave_id_t eid, const char *pw, int index,
                                int *app)
{
    *app = -1;
    return ecall_remove_item(eid, app, pw, index);
}

static int failures;

#define EXPECT(cond, fmt, ...)                                                \
    do {                                                                       \
        if (!(cond)) {                                                         \
            ++failures;                                                        \
            fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__,       \
                    ##__VA_ARGS__);                                            \
        }                                                                      \
    } while (0)

/***************************************************
 * Modes
 ***************************************************/
static int run_session(size_t sequence)
{
    sgx_enclave_id_t eid;
    int app;
    sgx_status_t st;
    static wallet_t wallet;
    item_t first = { "mail", "alice", "first-secret" };
    item_t second = { "vault", "bob", "second-secret" };
    size_t i;

    eid = create_enclave();
    if (eid == 0) {
        return 1;
    }

    /* create + show on the same enclave */
    st = call_create(eid, "password123", &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "create st=0x%x app=%d", st, app);

    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "show st=0x%x app=%d", st, app);
    EXPECT(wallet.size == 0 && strcmp(wallet.master_password, "password123") == 0,
           "wallet content after create");

    /* change, then an ordinary wrong-password error must not end the session */
    st = call_change(eid, "password123", "password456", &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "change st=0x%x app=%d", st, app);

    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == ERR_WRONG_MASTER_PASSWORD,
           "wrong password st=0x%x app=%d", st, app);

    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password456", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS && wallet.size == 0,
           "show after change st=0x%x app=%d", st, app);

    /* add two items and verify */
    st = call_add(eid, "password456", &first, sizeof(first), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "add1 st=0x%x app=%d", st, app);
    st = call_add(eid, "password456", &second, sizeof(second), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "add2 st=0x%x app=%d", st, app);

    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password456", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS && wallet.size == 2,
           "show two items st=0x%x app=%d size=%zu", st, app, wallet.size);
    EXPECT(memcmp(&wallet.items[0], &first, sizeof(first)) == 0 &&
           memcmp(&wallet.items[1], &second, sizeof(second)) == 0,
           "item order after adds");

    /* remove the first item, verify the second shifts down */
    st = call_remove(eid, "password456", 0, &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "remove st=0x%x app=%d", st, app);
    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password456", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS && wallet.size == 1,
           "show after remove st=0x%x app=%d size=%zu", st, app, wallet.size);
    EXPECT(memcmp(&wallet.items[0], &second, sizeof(second)) == 0,
           "item shift after remove");

    /* a long mixed sequence on the same live enclave: valid calls interleaved
     * with recoverable application errors; allocation metadata and the MAC key
     * must remain stable across many sequential entries. */
    for (i = 0; i < sequence; ++i) {
        item_t item = { "cycle", "user", "cycle-secret" };
        st = call_add(eid, "password456", &item, sizeof(item), &app);
        EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS,
               "sequence add %zu st=0x%x app=%d", i, st, app);
        if ((i % 10u) == 0u) {
            memset(&wallet, 0, sizeof(wallet));
            st = call_show(eid, "wrong-password", &wallet, sizeof(wallet), &app);
            EXPECT(st == SGX_SUCCESS && app == ERR_WRONG_MASTER_PASSWORD,
                   "sequence wrong-pw %zu st=0x%x app=%d", i, st, app);
        }
        st = call_remove(eid, "password456", 0, &app);
        EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS,
               "sequence remove %zu st=0x%x app=%d", i, st, app);
    }
    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password456", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS && wallet.size == 1,
           "show after sequence st=0x%x app=%d size=%zu", st, app, wallet.size);

    sgx_destroy_enclave(eid);
    g_active_eid = 0;

    /* a fresh enclave must see the same host-persistent sealed wallet */
    eid = create_enclave();
    if (eid == 0) {
        return 1;
    }
    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password456", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS && wallet.size == 1,
           "fresh enclave show st=0x%x app=%d size=%zu", st, app, wallet.size);
    sgx_destroy_enclave(eid);
    g_active_eid = 0;

    if (failures == 0) {
        printf("SESSION PASS (create/show/wrong-pw/change/add/add/show/remove/show, "
               "%zu cycle iterations, fresh enclave reconnected; wallet_t=%zu bytes)\n",
               sequence, sizeof(wallet_t));
        return 0;
    }
    printf("SESSION FAIL (%d)\n", failures);
    return 1;
}

static int boundary_case(const char *name, sgx_status_t got_transport,
                         int got_app, sgx_status_t want_transport, int want_app,
                         const uint8_t *output, size_t output_size)
{
    int ok = got_transport == want_transport && got_app == want_app;
    size_t i;
    if (output) {
        for (i = 0; i < output_size; ++i) {
            if (output[i] != 0) {
                ok = 0;
            }
        }
    }
    printf("boundary %s: %s (transport=0x%x app=%d want_transport=0x%x want_app=%d)\n",
           name, ok ? "PASS" : "FAIL", got_transport, got_app, want_transport,
           want_app);
    return ok ? 0 : 1;
}

static int run_boundary(void)
{
    sgx_enclave_id_t eid;
    int app;
    sgx_status_t st;
    static wallet_t wallet;
    item_t too_long = { 0 };
    item_t item = { "mail", "alice", "first-secret" };
    uint8_t output[sizeof(wallet_t) + 1];

    eid = create_enclave();
    if (eid == 0) {
        return 1;
    }
    st = call_create(eid, "password123", &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "boundary create st=0x%x app=%d",
           st, app);

    /* NULL and undersized object behavior is tested with controlled native
     * app stubs. The original app may dereference invalid inputs and abort. */
    /* Empty password reaches the application's own password policy. */
    st = call_create(eid, "", &app);
    failures += boundary_case("empty password", st, app, SGX_SUCCESS,
                              ERR_PASSWORD_OUT_OF_RANGE, NULL, 0);

    /* The original byte-length EDL imposes no record-size maximum. */
    memset(output, 0xa5, sizeof(output));
    st = call_show(eid, "password123", (wallet_t *)output, sizeof(output), &app);
    failures += boundary_case("output beyond old cap", st, app, SGX_SUCCESS,
                              RET_SUCCESS, NULL, 0);
    EXPECT(output[sizeof(wallet_t)] == 0, "SDK output tail initialized");

    /* ADD admits a larger byte buffer and the app consumes its item prefix. */
    unsigned char larger_item[sizeof(item_t) + 1];
    memcpy(larger_item, &item, sizeof(item));
    larger_item[sizeof(item)] = 0;
    st = call_add(eid, "password123", (const item_t *)larger_item, sizeof(larger_item), &app);
    failures += boundary_case("item beyond exact record size", st, app, SGX_SUCCESS,
                              RET_SUCCESS, NULL, 0);

    /* An input larger than the removed 4096-byte cap reaches app policy. */
    char long_password[5000];
    memset(long_password, 'p', sizeof(long_password) - 1);
    long_password[sizeof(long_password) - 1] = 0;
    st = call_create(eid, long_password, &app);
    failures += boundary_case("password beyond old cap", st, app, SGX_SUCCESS,
                              ERR_PASSWORD_OUT_OF_RANGE, NULL, 0);

    /* An over-long item reaches the application's own length policy. */
    memset(too_long.title, 'A', sizeof(too_long.title));
    memset(too_long.username, 'B', sizeof(too_long.username));
    memset(too_long.password, 'C', sizeof(too_long.password));
    too_long.password[sizeof(too_long.password) - 1] = 0;
    st = call_add(eid, "password123", &too_long, sizeof(too_long), &app);
    failures += boundary_case("item too long", st, app, SGX_SUCCESS,
                              ERR_ITEM_TOO_LONG, NULL, 0);

    /* Out-of-range removal index reaches the application's index policy. */
    st = call_remove(eid, "password123", 999, &app);
    failures += boundary_case("remove bad index", st, app, SGX_SUCCESS,
                              ERR_ITEM_DOES_NOT_EXIST, NULL, 0);

    /* Ordinary application errors must leave the session usable. */
    memset(&wallet, 0, sizeof(wallet));
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS,
           "recovery show st=0x%x app=%d", st, app);

    /* Host load refusal and corrupt sealed blob are ordinary app errors. */
    g_reply_mode = LOAD_FAIL;
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    failures += boundary_case("host load refusal", st, app, SGX_SUCCESS,
                              ERR_CANNOT_LOAD_WALLET, NULL, 0);
    g_reply_mode = BAD_BLOB_LENGTH;
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    failures += boundary_case("oversized blob length", st, app, SGX_SUCCESS,
                              ERR_FAIL_UNSEAL, NULL, 0);
    g_reply_mode = BAD_BLOB_MAC;
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    failures += boundary_case("corrupt blob", st, app, SGX_SUCCESS,
                              ERR_FAIL_UNSEAL, NULL, 0);
    g_reply_mode = REPLY_OK;

    /* Nested entry: an ECALL issued from inside an OCALL while the gate is held.
     * The SDK refuses the re-entrant entry before it can reach the adapter. */
    g_nested_attempted = 0;
    g_nested_status = SGX_SUCCESS;
    g_reply_mode = REENTER;
    st = call_show(eid, "password123", &wallet, sizeof(wallet), &app);
    g_reply_mode = REPLY_OK;
    EXPECT(g_nested_attempted == 1, "nested entry was not attempted");
    EXPECT(st == SGX_SUCCESS && app == RET_SUCCESS, "outer show st=0x%x app=%d",
           st, app);
    printf("boundary nested entry: %s (SDK refusal 0x%x)\n",
           g_nested_status == SGX_ERROR_ECALL_NOT_ALLOWED ? "PASS" : "FAIL",
           g_nested_status);
    if (g_nested_status != SGX_ERROR_ECALL_NOT_ALLOWED) {
        ++failures;
    }

    sgx_destroy_enclave(eid);
    g_active_eid = 0;

    if (failures == 0) {
        printf("BOUNDARY PASS\n");
        return 0;
    }
    printf("BOUNDARY FAIL (%d)\n", failures);
    return 1;
}

static int run_overflow(size_t wallet_size, uint32_t capacity)
{
    sgx_enclave_id_t eid;
    int app;
    sgx_status_t st;
    uint8_t *buffer;

    eid = create_enclave();
    if (eid == 0) {
        return 1;
    }
    st = call_create(eid, "password123", &app);
    if (st != SGX_SUCCESS || app != RET_SUCCESS) {
        fprintf(stderr, "FAIL: overflow create st=0x%x app=%d\n", st, app);
        sgx_destroy_enclave(eid);
        return 1;
    }

    buffer = (uint8_t *)malloc(capacity == 0 ? 1 : capacity);
    if (buffer == NULL) {
        sgx_destroy_enclave(eid);
        return 1;
    }
    memset(buffer, 0, capacity);
    printf("overflow probe: sizeof(wallet_t)=%zu wallet_size=%zu "
           "host_backing=%u\n", sizeof(wallet_t), wallet_size, capacity);
    /* Flush before the ECALL: when the probe is run under a batch debugger,
     * stdout is a pipe/file and the buffer would otherwise be lost when the
     * enclave traps inside the call. The attribution oracle needs this
     * observed backing-size record. */
    fflush(stdout);
    /* The EDL wallet_size controls both SDK marshaling and the protected
     * application allocation. The host backing buffer size is a host-side
     * variation and does not change either. */
    st = call_show(eid, "password123", (wallet_t *)buffer, wallet_size, &app);
    printf("overflow probe returned: transport=0x%x app=%d\n", st, app);
    free(buffer);
    sgx_destroy_enclave(eid);
    g_active_eid = 0;
    /* Any normal return is not an identified ENCBound rejection; the security
     * target uses the debugger oracle to attribute the terminal check. */
    return 1;
}

int main(int argc, char **argv)
{
    size_t wallet_size = 16;
    uint32_t capacity = 0;
    size_t sequence = 64;
    int overflow = 0;
    int boundary = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--overflow") == 0) {
            overflow = 1;
        } else if (strcmp(argv[i], "--boundary") == 0) {
            boundary = 1;
        } else if (strcmp(argv[i], "--wallet-size") == 0 && i + 1 < argc) {
            wallet_size = (size_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--capacity") == 0 && i + 1 < argc) {
            capacity = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--sequence") == 0 && i + 1 < argc) {
            sequence = (size_t)strtoul(argv[++i], NULL, 0);
        }
    }

    if (boundary) {
        return run_boundary();
    }
    if (overflow) {
        return run_overflow(wallet_size,
                            capacity == 0 ? (uint32_t)wallet_size : capacity);
    }
    return run_session(sequence);
}
