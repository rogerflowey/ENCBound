#ifndef SK_VULN_NATIVE_SHIM_H
#define SK_VULN_NATIVE_SHIM_H

/*
 * The pinned enclave is normally compiled against Intel tlibc headers, which
 * declare these two SDK/TLS services.  The native harness uses ordinary libc
 * headers, so declare the exact names it links from the recording stubs.
 */
#include <stddef.h>

int memset_s(void *s, size_t smax, int c, size_t n);
int consttime_memequal(const void *a, const void *b, size_t len);

#endif
