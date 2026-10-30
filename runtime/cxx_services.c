#include <stdlib.h>
/* Terminal no-exception library failures. Diagnostic strings are deliberately
 * not dereferenced by this service; failure always terminates the enclave. */
_Noreturn void encbound_cxx_fail(void) { abort(); }
_Noreturn void encbound_cxx_assert(const char *file, int line,
                                 const char *function, const char *expression)
{ (void)file; (void)line; (void)function; (void)expression; abort(); }

/* Pure scalar math service used by unordered-container capacity calculation. */
#include <math.h>
float encbound_cxx_ceilf(float x) { return ceilf(x); }
