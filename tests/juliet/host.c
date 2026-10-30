#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "juliet_u.h"

static uint64_t digest = UINT64_C(14695981039346656037);
static uint64_t events;
static unsigned entered, returned;
static uint32_t expected;
void juliet_observe(uint32_t kind, uint64_t value)
{
    if (kind >= 100) {
        printf("JULIET_EVENT kind=%u value=%llu\n", kind,
               (unsigned long long)value);
        fflush(stdout);
        if (kind == 100 && value == expected) ++entered;
        if (kind == 101 && value == expected) ++returned;
        return;
    }
    ++events;
    for (unsigned i = 0; i < 4; ++i) {
        digest = (digest ^ ((kind >> (8*i)) & 255)) * UINT64_C(1099511628211);
    }
    for (unsigned i = 0; i < 8; ++i) {
        digest = (digest ^ ((value >> (8*i)) & 255)) * UINT64_C(1099511628211);
    }
}
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    char *end;
    unsigned long id = strtoul(argv[1], &end, 10);
    if (*end || id > UINT32_MAX) return 2;
    expected = (uint32_t)id;
    unsigned long bad = strtoul(argv[2], &end, 10);
    if (*end || bad > 1) return 2;
    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG,
                                            NULL, NULL, &eid, NULL);
    if (status != SGX_SUCCESS) {
        printf("JULIET_CREATE_ERROR %x\n", status); return 3;
    }
    int result = -1;
    status = juliet_run(eid, &result, expected, (uint32_t)bad);
    sgx_status_t destroy = sgx_destroy_enclave(eid);
    if (status != SGX_SUCCESS || result || destroy != SGX_SUCCESS ||
        entered != 1 || returned != 1) {
        printf("JULIET_ERROR transport=%x result=%d destroy=%x entered=%u returned=%u\n",
               status, result, destroy, entered, returned); return 4;
    }
    printf("JULIET_RETURN case=%u bad=%lu events=%llu digest=%016llx\n",
           expected, bad, (unsigned long long)events, (unsigned long long)digest);
    return 0;
}
