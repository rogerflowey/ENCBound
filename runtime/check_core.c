/* Optional trusted-only compilation unit for the benchmark optimization study.
 * Compile this INSTEAD OF siphash.c, runtime.c and capability.c. Exposing their
 * definitions to the same optimizer removes private helper call/serialization
 * overhead without LTO across the instrumented application boundary. These
 * are the same implementations and public ABI; no check or MAC is elided.
 * Platform binding, allocator, adapters and application code remain separate.
 */
#include "siphash.c"
/* Only this trusted unit sees the inline implementation. The public API and
 * separate compilation path remain available; applications still call the
 * out-of-line encbound_require entry and never receive key access. */
#define encbound_siphash24_fixed6 siphash24_fixed6_inline
#include "runtime.c"
#undef encbound_siphash24_fixed6
#include "capability.c"
