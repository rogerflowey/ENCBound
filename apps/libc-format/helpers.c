/* Application-owned support for the selected formatter, not SDK libc state.
 * errno is supplied by the common application environment in libc/errno.c. */
#include <stddef.h>
void *memchr(const void *p, int value, size_t n) {
    const unsigned char *s=p;
    for (size_t i=0;i<n;++i) if (s[i]==(unsigned char)value) return (void *)(s+i);
    return NULL;
}
