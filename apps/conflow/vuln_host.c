/* Hostile-shape control driver for the selected ConFlow softmax ECALLs.
 *
 * The default functional host (host.c) is unchanged. This driver calls the
 * original eight-operator EDL with dimensions that the application does not
 * validate: softmax/softmax_grad allocate enclave scratch from N but index it
 * as M rows of C elements. N < M*C therefore crosses the protected allocation.
 * No input array itself is malformed or shortened; only N/M/C disagree.
 *
 * Exit status: 0 when the ECALL returns (the checked profiles only do this for
 * accepted/valid modes), otherwise the SDK SIM process dies with the check's
 * signal (SIGILL for ENCBound, SIGSEGV for the baseline heap corruption).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

#define MAX_N 64
#define SHARES 5
#define INPUT_FLOATS (5 * MAX_N)
#define OUTPUT_FLOATS (SHARES * MAX_N + 2)

__attribute__((noinline)) void conflow_trace_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

static void fill(float *input, float *grad)
{
    for (int i = 0; i < INPUT_FLOATS; ++i) {
        input[i] = (float)((i % 17) - 8) * 0.125f;
        grad[i] = (float)((i % 13) - 6) * 0.25f;
    }
}

static int call(sgx_enclave_id_t eid, const char *mode, int n, int m, int c,
                int gradient)
{
    float input[INPUT_FLOATS];
    float grad[INPUT_FLOATS];
    float output[OUTPUT_FLOATS];
    fill(input, grad);
    for (int i = 0; i < OUTPUT_FLOATS; ++i) {
        output[i] = 1234567.0f;
    }
    sgx_status_t status = gradient
        ? ecall_softmax_grad(eid, input, grad, n, m, c, output + 1)
        : ecall_softmax(eid, input, n, m, c, output + 1);
    printf("{\"mode\":\"%s\",\"N\":%d,\"M\":%d,\"C\":%d,\"status\":%u}\n",
           mode, n, m, c, (unsigned)status);
    fflush(stdout);
    return status == SGX_SUCCESS ? 0 : 20;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <enclave.signed.so> <mode>\n", argv[0]);
        return 2;
    }
    const char *image = argv[1];
    const char *mode = argv[2];
    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL,
                                             &eid, NULL);
    if (status) {
        fprintf(stderr, "create=%#x\n", (unsigned)status);
        return 3;
    }
    conflow_trace_ready();
    four_app_permissions(image);

    int rc;
    if (!strcmp(mode, "softmax-valid")) {
        rc = call(eid, mode, 4, 1, 4, 0);
    } else if (!strcmp(mode, "softmax-shape")) {
        rc = call(eid, mode, 4, 1, 5, 0);
    } else if (!strcmp(mode, "softmax-shape-large")) {
        rc = call(eid, mode, 32, 1, 33, 0);
    } else if (!strcmp(mode, "softmax-grad-valid")) {
        rc = call(eid, mode, 4, 1, 4, 1);
    } else if (!strcmp(mode, "softmax-grad-shape")) {
        rc = call(eid, mode, 4, 1, 5, 1);
    } else if (!strcmp(mode, "softmax-negative-c")) {
        rc = call(eid, mode, 4, 2, -1, 0);
    } else if (!strcmp(mode, "softmax-grad-negative-c")) {
        rc = call(eid, mode, 4, 2, -1, 1);
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode);
        rc = 2;
    }
    if (rc == 0 && sgx_destroy_enclave(eid) != SGX_SUCCESS) {
        rc = 4;
    }
    return rc;
}
