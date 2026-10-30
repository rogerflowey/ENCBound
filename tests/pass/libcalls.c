/* ENCBound step 4/5 sample: raw library calls are redirected to adapters.
 * Compiled with -fno-builtin so the calls stay as direct calls in the IR. */
#include <stddef.h>

extern void *memcpy(void *dst, const void *src, size_t n);
extern size_t strlen(const char *s);

size_t dup(char *dst, const char *src)
{
    memcpy(dst, src, 8);
    return strlen(dst);
}
