#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sgx_urts.h>
#include "test_sdk_u.h"
#include "../../tests/cxx-lifecycle/loaded_permissions.h"
int main(int argc,char **argv)
{
    if(argc!=2 && argc!=3)return 1;
    sgx_enclave_id_t id=0;
    sgx_status_t s=sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,0,0,&id,0);
    if(s!=SGX_SUCCESS){fprintf(stderr,"create=0x%x\n",s);return 2;}
    permissions(argv[1]);
    if(argc==3){int value=-999;s=adapter_probe(id,&value,atoi(argv[2]));
        printf("CONTROL_RETURN status=0x%x value=%d\n",s,value);return 0;}
    for(int repeat=0;repeat<9;++repeat)for(int action=0;action<5;++action){
        int value=-999;s=adapter_probe(id,&value,action);
        if(s!=SGX_SUCCESS || value!=1){fprintf(stderr,"action=%d status=0x%x value=%d\n",action,s,value);return 3;}
    }
    if(sgx_destroy_enclave(id)!=SGX_SUCCESS)return 4;
    puts("YEEZ SDK ADAPTER SIM PASS calls=45 crypto_vectors=9 valid_DH=27 bad_DH=9");
    return 0;
}
