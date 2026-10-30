/* Deterministic saved-prediction fixtures; no ML training framework needed.
 * Uses the original user_check ECALL and checks both transport and app result.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

void ocall_print(const char *message) { fprintf(stderr, "%s\n", message); }

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (status) { fprintf(stderr,"create=%#x\n", status); return 3; }
    four_app_permissions(argv[1]);
    ModelInput *input = calloc(MODEL_NUM, sizeof(*input));
    CombinerOutput *output = malloc(sizeof(*output));
    if (!input || !output) return 4;
    for (int test = 0; test < 6; ++test) {
        memset(output, 0, sizeof(*output));
        output->iteration = 0x12345678;
        for (int i = 0; i < MODEL_NUM; ++i) {
            input[i].weight = -999; /* init_model_inputs must reset this */
            for (int j = 0; j < QUERY_SIZE; ++j)
                for (int k = 0; k < CATEGORY_NUM; ++k)
                    input[i].preds[j][k] = test == 0 ? 0 : test == 1 ? (k+1)/55.0 :
                        (1+((i+1)*(k+3)+(j+2)*(test+1))%31)/100.0;
        }
        int result = -99;
        status = combine_result(eid, &result, input, output);
        if (status || result || output->iteration != 0x12345678) {
            fprintf(stderr,"combine=%#x result=%d iteration=%d\n", status, result, output->iteration);
            return 5;
        }
        for (int i = 0; i < MODEL_NUM; ++i)
            for (int j = 0; j < QUERY_SIZE; ++j)
                for (int k = 0; k < CATEGORY_NUM; ++k) {
                    double expected = test == 0 ? 0 : test == 1 ? (k+1)/55.0 :
                        (1+((i+1)*(k+3)+(j+2)*(test+1))%31)/100.0;
                    if (input[i].preds[j][k] != expected) return 7;
                }
        printf("{\"case\":%d,\"weights\":[",test);
        for (int i = 0; i < MODEL_NUM; ++i) printf("%s%.17g",i?",":"",input[i].weight);
        printf("],\"preds\":[");
        for (int j = 0; j < QUERY_SIZE; ++j)
            for (int k = 0; k < CATEGORY_NUM; ++k)
                printf("%s%.17g",j||k?",":"",output->preds[j][k]);
        puts("]}");
    }
    free(output); free(input);
    return sgx_destroy_enclave(eid) == SGX_SUCCESS ? 0 : 6;
}
