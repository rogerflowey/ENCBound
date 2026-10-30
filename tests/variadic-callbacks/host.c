/* Reuses tests/cxx-lifecycle's loaded-page checker; SDK SIM only. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "probe_u.h"
#include "../cxx-lifecycle/loaded_permissions.h"

int main(int argc, char **argv)
{
    assert(argc==2 || argc==3);
    sgx_enclave_id_t enclave;
    assert(sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &enclave, NULL)==SGX_SUCCESS);
    permissions(argv[1]);
    long result=-1;
    if (argc==3) {
        unsigned long target=0;
        assert(callback_target(enclave, &target)==SGX_SUCCESS && target);
        assert(indirect_case(enclave, &result, (unsigned char *)target, atoi(argv[2]))==SGX_SUCCESS);
        assert(result==0);
        puts("INDIRECT VARIADIC BASELINE PRIVATE WRITE PASS");
    } else {
        for (unsigned i=0; i<20; ++i) {
            unsigned char byte=11;
            assert(indirect_case(enclave, &result, &byte, 0)==SGX_SUCCESS);
            assert(result==1023 && byte==12);
        }
        puts("INDIRECT VARIADIC SDK SIM PASS cases=20 bits=1023");
    }
    assert(sgx_destroy_enclave(enclave)==SGX_SUCCESS);
    return 0;
}
