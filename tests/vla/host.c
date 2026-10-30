#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "probe_u.h"
int main(int argc,char **argv) {
    assert(argc==2 || argc==3);
    sgx_enclave_id_t eid;
    assert(sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL)==SGX_SUCCESS);
    int result=-999;
    if (argc==3) {
        int mode=atoi(argv[2]);
        size_t n=mode==1 ? 0 : mode==2 ? SIZE_MAX/4+1 : mode==3 ? (1ul<<28) : mode==6 ? SIZE_MAX/3+1 : 5;
        assert(run_test(eid,&result,n,mode)==SGX_SUCCESS);
        return 90; /* terminal controls must never return */
    }
    for (unsigned i=0;i<6;++i) {
        size_t n=(size_t[]){17,33,129}[i%3];
        assert(run_test(eid,&result,n,0)==SGX_SUCCESS && result==0);
    }
    assert(sgx_destroy_enclave(eid)==SGX_SUCCESS);
    puts("VLA SDK SIM PASS: 6 sequential ECALLs, scope reclamation and cleared slots");
    return 0;
}
