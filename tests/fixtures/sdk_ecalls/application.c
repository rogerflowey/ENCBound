#include "probe_t.h"

int application(unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) p[i] += 1;
    /* The native host observes the exact application pointer bits and tries
     * both entry classes while the application's OCALL is active. */
    return observe(p) == SGX_SUCCESS ? 41 : -1;
}
