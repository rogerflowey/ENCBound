#include <assert.h>
#include <stdio.h>
#include "sgx_urts.h"
#include "probe_u.h"
#include "loaded_permissions.h"
int main(int argc,char **argv) {
    assert(argc==2); sgx_enclave_id_t eid;
    assert(sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL)==SGX_SUCCESS);
    permissions(argv[1]);
    int result=-99;
    assert(exercise(eid,&result,0)==SGX_SUCCESS && result==170);
    for(unsigned i=0;i<8;++i) assert(exercise(eid,&result,2)==SGX_SUCCESS && result==240);
    assert(isolation(eid,&result)==SGX_SUCCESS && result==0);
    assert(test_finalize(eid,&result)==SGX_SUCCESS && result==0);
    // Draining the SDK registry twice must not invoke any callback twice.
    assert(test_finalize(eid,&result)==SGX_SUCCESS && result==0);
    assert(test_finish_arrays(eid,&result)==SGX_SUCCESS && result==0);
    assert(sgx_destroy_enclave(eid)==SGX_SUCCESS);
    puts("CXX LIFECYCLE SDK SIM PASS: constructors, local statics, ODR, array destructors, reverse order");
    return 0;
}
