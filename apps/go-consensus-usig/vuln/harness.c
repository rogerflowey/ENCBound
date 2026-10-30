/* Native ASan harness for the pinned USIG enclave source.
 *
 * This is a vulnerability dig, not an SGX execution result.  The five ECALL
 * bodies are called directly with host-sized inputs; sgx_* and crypto_sign_*
 * are local stand-ins (see stubs/sgx_glue.c).  AddressSanitizer attributes the
 * out-of-bounds accesses in the unmodified upstream source. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_tcrypto.h>
#include "usig_enclave.h"
#include "usig_enclave_t.h"

#define BUF 2048
static unsigned char key[BUF];
static unsigned char sk[BUF];
static unsigned char digest[32];
static unsigned char sig[128];
static sgx_ec256_private_t priv = {{1}};
static uint64_t ctr;

static void init(unsigned mackey_len, unsigned ed_len, unsigned counters)
{
    ecall_usig_init((const char *)key, mackey_len, priv, counters,
                    (const char *)sk, ed_len);
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    memset(key, 'K', sizeof key);
    memset(sk, 'S', sizeof sk);
    memset(digest, 0x22, sizeof digest);

    if (!strcmp(argv[1], "mackey-1025")) {
        init(1025, 64, 3);
    } else if (!strcmp(argv[1], "edkey-1024")) {
        init(32, 1024, 3);
    } else if (!strcmp(argv[1], "edkey-1060")) {
        init(32, 1060, 3);
    } else if (!strcmp(argv[1], "counter-oob")) {
        init(32, 64, 3);
        ecall_usig_create_ui_sig_edd25519(digest, 4, &ctr, sig, 64);
    } else if (!strcmp(argv[1], "counter-in-range")) {
        init(32, 64, 3);
        ecall_usig_create_ui_sig_edd25519(digest, 2, &ctr, sig, 64);
        if (ctr != 1)
            return 4;
        puts("COUNTER-IN-RANGE PASS");
        return 0;
    } else {
        return 3;
    }
    fprintf(stderr, "case %s returned without an ASan report\n", argv[1]);
    return 0;
}
