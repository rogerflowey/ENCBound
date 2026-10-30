/* Trusted, optional SDK startup entry. Link before equal-priority entries and
 * audit the final DT_INIT_ARRAY with tools/check_early_bootstrap.py. */
#include "boundary_support.h"
#include "encbound_platform.h"
#include "encbound_common.h"

void encbound_early_bootstrap(void)
{
    if (encbound_boundary_initialize() != 0) {
        encbound_boundary_fail();
        encbound_abort(ENCBOUND_ERR_STATE);
    }
}

__attribute__((used, section(".init_array.00000")))
static void (*const encbound_early_bootstrap_entry)(void) =
    encbound_early_bootstrap;
