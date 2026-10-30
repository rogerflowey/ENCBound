#include <errno.h>
#include <stdint.h>
#include "probe_t.h"

int errno_dependency_read(void);
int errno_dependency_write(int value);

int errno_case(int action, int initial, int value, int result, int *observed)
{
    observed[0] = errno;
    errno = initial;
    observed[1] = errno_dependency_read();
    int returned = -900;
    int words[2] = {11, 22};
    sgx_status_t status = SGX_SUCCESS;
    switch (action) {
    case 0: status = errno_exchange(&returned, value, result, words); break;
    case 1: status = errno_void(value); break;
    case 2: status = errno_plain(&returned, value, result); break;
    case 3: status = errno_naked(); break;
    case 4: errno_dependency_write(value); break;
    default: return -901;
    }
    observed[2] = (int)status;
    observed[3] = returned;
    observed[4] = words[0];
    observed[5] = words[1];
    observed[6] = errno;
    observed[7] = errno_dependency_read();
    return errno;
}

int errno_read(void) { return errno; }
int errno_write(int value) { return errno_dependency_write(value); }
uintptr_t errno_pointer(void) { return (uintptr_t)&errno; }
int errno_access(int *pointer, int write)
{
    if (write) *pointer = 0x1357;
    return *pointer;
}
