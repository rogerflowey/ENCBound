/* Declarations from pinned SDK tlibc/string.h for the native host-libc test.
 * Production builds consume the actual SDK header. Definitions in
 * adapters_test.c record raw calls; this header does not enter enclave builds. */
#include <stddef.h>
int consttime_memequal(const void *, const void *, size_t);
int memset_s(void *, size_t, int, size_t);
