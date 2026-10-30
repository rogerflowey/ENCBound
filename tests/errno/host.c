/* Independent matched SDK SIM errno/session oracle; no hardware claim. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "probe_u.h"
#include "../cxx-lifecycle/loaded_permissions.h"
void errno_host_prepare(int);
int errno_host_captured(void);

int main(int argc, char **argv)
{
    assert(argc==2 || argc==3);
    sgx_enclave_id_t enclave;
    assert(sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &enclave, NULL) == SGX_SUCCESS);
    permissions(argv[1]);
    if (argc==3) {
        uintptr_t target=0; int result=-1;
        assert(errno_sdk_address(enclave, &target) == SGX_SUCCESS && target);
        int write=!strcmp(argv[2], "sdk-write");
        assert(write || !strcmp(argv[2], "sdk-read"));
        assert(errno_access(enclave, &result, (int *)target, write) == SGX_SUCCESS);
        assert(result == (write ? 0x1357 : 0x5a17));
        assert(errno_sdk_read(enclave, &result) == SGX_SUCCESS && result == (write ? 0x1357 : 0x5a17));
        assert(sgx_destroy_enclave(enclave) == SGX_SUCCESS);
        puts("ERRNO SDK RAW ACCESS BASELINE PASS"); return 0;
    }
    int previous=0, observed[8], result=-1;
    assert(errno_read(enclave, &result) == SGX_SUCCESS && result == 0);
    const int values[]={0, ENOENT, EACCES, INT_MAX, -71, INT_MIN};
    unsigned cases=0;
    for (unsigned repetition=0; repetition<2; ++repetition)
    for (unsigned i=0; i<sizeof values/sizeof values[0]; ++i)
    for (int action=0; action<5; ++action) {
        uintptr_t sdk_address=0;
        assert(errno_sdk_address(enclave, &sdk_address) == SGX_SUCCESS && sdk_address);
        errno_host_prepare(317);
        int value=values[i], initial=200+(int)cases, returned=cases%2 ? -1 : 97;
        assert(errno_case(enclave, &result, action, initial, value, returned, observed) == SGX_SUCCESS);
        int captured=errno_host_captured();
        int expected=action==2 ? initial : action==4 ? value : captured;
        if (action<2 && value!=INT_MIN) assert(captured==value);
        assert(result == expected && observed[0] == previous && observed[1] == initial);
        assert(observed[2] == SGX_SUCCESS && observed[6] == expected && observed[7] == expected);
        assert(observed[3] == (action==0 || action==2 ? returned : -900));
        assert(observed[4] == (action==0 ? 33 : 11) && observed[5] == (action==0 ? 44 : 22));
        assert(errno_sdk_read(enclave, &result) == SGX_SUCCESS && result == (action==2 || action==4 ? 0x5a17 : expected));
        assert(errno_read(enclave, &result) == SGX_SUCCESS && result == expected);
        previous=expected; ++cases;
    }
    uintptr_t sdk_address=0, app_pointer=0;
    assert(errno_sdk_address(enclave, &sdk_address) == SGX_SUCCESS);
    assert(errno_write(enclave, &result, 83) == SGX_SUCCESS && result == 83);
    assert(errno_sdk_read(enclave, &result) == SGX_SUCCESS && result == 0x5a17);
    assert(errno_read(enclave, &result) == SGX_SUCCESS && result == 83);
    assert(errno_pointer(enclave, &app_pointer) == SGX_SUCCESS && app_pointer && app_pointer!=sdk_address);
    assert(sgx_destroy_enclave(enclave) == SGX_SUCCESS);
    printf("ERRNO SDK SIM PASS cases=%u\n", cases);
    return 0;
}
