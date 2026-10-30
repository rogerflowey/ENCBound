/* Isolated bootstrap ordering/failure unit controls; no protection claim. */
#include <stdlib.h>
#include "encbound_common.h"
static int initialized, failed, observed;
int encbound_boundary_initialize(void) {
    ++initialized;
#ifdef FAIL_INIT
    return -1;
#else
    return 0;
#endif
}
void encbound_boundary_fail(void) { failed = 1; }
_Noreturn void encbound_abort(int code) {
    _Exit(code == ENCBOUND_ERR_STATE && failed && initialized == 1 ? 71 : 72);
}
static void observer(void) { observed = initialized == 1 && !failed; }
__attribute__((used,section(".init_array.00000")))
static void (*const entry)(void) = observer;
int main(void) { return observed && initialized == 1 && !failed ? 0 : 73; }
