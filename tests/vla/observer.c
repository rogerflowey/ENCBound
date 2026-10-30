/* Trusted diagnostic observer only; never part of a production service. */
#include <stddef.h>
#include <stdint.h>
#ifdef PROTECTED
#include "encbound_runtime.h"
#endif
uintptr_t vla_last_raw;
size_t vla_last_size;
unsigned vla_observations;
int vla_observe(const void *p, size_t rounded) {
    uintptr_t raw=(uintptr_t)p;
#ifdef PROTECTED
    size_t extent=0;
    if (encbound_check_extent((uintptr_t)p,&raw,&extent) || extent!=rounded ||
        (raw&(rounded-1))) return 0;
    for (size_t i=0;i<rounded;++i) if (((unsigned char *)raw)[i]) return 0;
    /* Dirty padding too: the next reuse must clear the whole slot. */
    ((unsigned char *)raw)[rounded-1]=0x5a;
#endif
    vla_last_raw=raw; vla_last_size=rounded; ++vla_observations;
    return 1;
}
size_t vla_edge(const void *p) {
    (void)p;
    return vla_last_size-1;
}
