/* Native SDK-copy shim: exercise emitted bridge control flow, not SGX. */
#ifndef TEST_MBSAFE_H
#define TEST_MBSAFE_H
#include <stddef.h>
#include <string.h>
extern int bridge_copy_fail;
static inline int memcpy_s(void *d, size_t cap, const void *s, size_t n)
{
    if (bridge_copy_fail > 0 && --bridge_copy_fail == 0) return 1;
    if (n > cap || (n && (!d || !s))) return 1;
    if (n) memcpy(d, s, n);
    return 0;
}
static inline int memcpy_verw_s(void *d, size_t cap, const void *s, size_t n)
{ return memcpy_s(d, cap, s, n); }
static inline void memset_verw(void *d, int v, size_t n)
{ if (n) memset(d, v, n); }
#endif
