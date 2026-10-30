/* Native fault injection into real generated copy-back control flow. */
#ifndef ERRNO_TEST_MBSAFECRT_H
#define ERRNO_TEST_MBSAFECRT_H
#include <stddef.h>
#include <string.h>
extern int bridge_copy_fail;
void errno_test_after_copy(const void *source, size_t size);
static inline int memcpy_s(void *dest, size_t capacity, const void *source, size_t size)
{
    if (bridge_copy_fail > 0 && --bridge_copy_fail == 0) return 1;
    if (size > capacity || (size && (!dest || !source))) return 1;
    if (size) memcpy(dest, source, size);
    errno_test_after_copy(source, size);
    return 0;
}
static inline int memcpy_verw_s(void *d, size_t c, const void *s, size_t n)
{ return memcpy_s(d, c, s, n); }
static inline void memset_verw(void *d, int v, size_t n)
{ if (n) memset(d, v, n); }
#endif
