/* Test-only SDK errno address/value oracle; compiled as trusted SDK code. */
#include <errno.h>
#include <stdint.h>
uintptr_t errno_sdk_address(void) { errno = 0x5a17; return (uintptr_t)&errno; }
int errno_sdk_read(void) { return errno; }
