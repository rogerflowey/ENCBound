/* SDK SIM harness. Internal scaffolding origin: apps/go-consensus-usig and
 * apps/conflow. Required upstream ECALLs are called without changing bodies. */
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#include <openssl/hmac.h>
#include "Enclave_u.h"
#include "../four_app_permissions.h"

static unsigned calls, comparisons;

#ifdef APP_POSUP
static int compare(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y)-(x < y);
}

static void posup(sgx_enclave_id_t eid)
{
    int inputs[][12] = {{0}, {5}, {3,-3,1,0,-5,5}, {INT_MAX,-17,2,2,-17},
                        {12,11,10,9,8,7,6,5,4,3,2,1}, {0}};
    int lengths[] = {0,1,6,5,12,0};
    for (int round = 0; round < 3; ++round) {
        for (unsigned fixture = 0; fixture < sizeof(lengths)/sizeof(*lengths); ++fixture) {
            int expected[12], output[14], source[12];
            int n = lengths[fixture];
            memcpy(source, inputs[fixture], sizeof(source));
            for (int i = 0; i < n; ++i) expected[i] = abs(source[i]);
            qsort(expected, n, sizeof(int), compare);
            int unique = 0;
            for (int i = 0; i < n; ++i)
                if (!i || expected[i] != expected[i-1]) expected[unique++] = expected[i];
            assert(ecall_setFileIDs(eid, (unsigned char *)source, n) == SGX_SUCCESS); ++calls;
            assert(!memcmp(source, inputs[fixture], sizeof(source)));
            for (int i = 0; i < 14; ++i) output[i] = -98765;
            int got = -1;
            assert(diagnostic_fileids(eid, &got, output+1, 12) == SGX_SUCCESS); ++calls;
            assert(got == unique);
            for (int i = 0; i < unique; ++i) { assert(output[i+1] == expected[i]); ++comparisons; }
            for (int i = unique; i < 12; ++i) { assert(output[i+1] == 0); ++comparisons; }
            assert(output[0] == -98765 && output[13] == -98765);
            int path = -1;
            assert(ecall_getPathID(eid, &path) == SGX_SUCCESS); ++calls;
            assert(path == 0); ++comparisons;
        }
    }
}
#endif

#ifdef APP_TRUSTFL
enum { RECORDS = 60000, PIXELS = 784, MAC = 32 };

static void invoke(sgx_enclave_id_t eid, unsigned char *data, unsigned char *labels,
                   unsigned char *output, unsigned int data_length, unsigned int label_length)
{
    int result = 99;
    assert(ecall_data_preprocess(eid, &result, data, data_length, labels, label_length,
                               (unsigned long)(uintptr_t)output) == SGX_SUCCESS); ++calls;
    assert(result == 0);
}

static void trustfl(sgx_enclave_id_t eid)
{
    size_t data_size = 16+(size_t)RECORDS*PIXELS, label_size = 8+RECORDS;
    unsigned char *data = malloc(data_size), *labels = malloc(label_size);
    unsigned char *buffer = malloc((size_t)RECORDS*MAC+2), *again = malloc((size_t)RECORDS*MAC);
    assert(data && labels && buffer && again);
    memset(data, 0x55, 16); memset(labels, 0x66, 8);
    for (int i = 0; i < RECORDS; ++i) {
        for (int j = 0; j < PIXELS; ++j) data[16+(size_t)i*PIXELS+j] = (unsigned char)(j*7+(i%3)*11);
        labels[8+i] = (unsigned char)(i%3);
    }
    unsigned char *output = buffer+1;
    buffer[0] = 0x5a; buffer[(size_t)RECORDS*MAC+1] = 0xa5;
    /* Explicit pre-init diagnostic: the original static key is all zero.
     * This permits an independent OpenSSL check of every byte without exposing
     * a generated enclave key. It is separate from the initialized-key calls. */
    invoke(eid, data, labels, output, (unsigned int)data_size, (unsigned int)label_size);
    unsigned char key[128] = {0}, message[PIXELS+1], expected[3][MAC];
    for (int i = 0; i < 3; ++i) {
        memcpy(message, data+16+(size_t)i*PIXELS, PIXELS); message[PIXELS] = labels[8+i];
        unsigned int len = 0;
        assert(HMAC(EVP_sha256(), key, sizeof(key), message, sizeof(message), expected[i], &len));
        assert(len == MAC);
    }
    for (int i = 0; i < RECORDS; ++i) { assert(!memcmp(output+(size_t)i*MAC, expected[i%3], MAC)); comparisons += MAC; }
    assert(buffer[0] == 0x5a && buffer[(size_t)RECORDS*MAC+1] == 0xa5);
    assert(ecall_init(eid) == SGX_SUCCESS); ++calls;
    invoke(eid, data, labels, output, (unsigned int)data_size, (unsigned int)label_size);
    for (int i = 0; i < RECORDS; ++i) { assert(!memcmp(output+(size_t)i*MAC, output+(i%3)*MAC, MAC)); comparisons += MAC; }
    assert(memcmp(output, expected[0], MAC));
    /* Source ignores lengths. Zero scalar lengths below retain complete valid
     * host arrays; this tests that behavior without an out-of-bounds request. */
    invoke(eid, data, labels, again, 0, 0);
    assert(!memcmp(output, again, (size_t)RECORDS*MAC)); comparisons += RECORDS*MAC;
    labels[8+123] ^= 1;
    invoke(eid, data, labels, again, (unsigned int)data_size, (unsigned int)label_size);
    for (int i = 0; i < RECORDS; ++i) {
        assert((memcmp(output+(size_t)i*MAC, again+(size_t)i*MAC, MAC) != 0) == (i == 123));
        ++comparisons;
    }
    assert(buffer[0] == 0x5a && buffer[(size_t)RECORDS*MAC+1] == 0xa5);
    assert(data[0] == 0x55 && labels[0] == 0x66);
    free(again); free(buffer); free(labels); free(data);
}
#endif

int main(int argc, char **argv)
{
    assert(argc == 2);
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t status = sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (status != SGX_SUCCESS) { fprintf(stderr, "sgx_create_enclave=%#x\n", status); return 1; }
    four_app_permissions(argv[1]);
#ifdef APP_POSUP
    posup(eid);
#else
    trustfl(eid);
#endif
    assert(sgx_destroy_enclave(eid) == SGX_SUCCESS);
    printf("{\"result\":\"PASS\",\"calls\":%u,\"comparisons\":%u}\n", calls, comparisons);
    return 0;
}
