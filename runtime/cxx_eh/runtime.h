/* Trusted diagnostics only. These symbols are never application-admitted. */
#ifndef ENCBOUND_CXX_EH_PRIVATE_DIAGNOSTICS_H
#define ENCBOUND_CXX_EH_PRIVATE_DIAGNOSTICS_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
struct encbound_eh_stats_t {
    size_t live,peak,bytes,peak_bytes,header_size;
    size_t rounded,peak_rounded,allocations,unwind_offset;
};
struct encbound_eh_stats_t encbound_eh_stats(void);
void encbound_eh_boundary_clean(void);
#ifdef __cplusplus
}
#endif
#endif
