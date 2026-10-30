/* Trusted test-only serial-gate diagnostic; never admitted as an app service. */
#include "boundary_support.h"

int crust_selected_serial_check(void)
{
#ifdef ENCBOUND_PROTECTED
    /* The generated bridge already holds admission for this invocation. */
    return encbound_boundary_admit() == 0 ? -1 : 0;
#else
    /* Stock BASELINE bridges use SDK serial execution; test the gate alone. */
    if (encbound_boundary_admit() != 0)
        return -2;
    int nested = encbound_boundary_admit();
    encbound_boundary_release();
    return nested == 0 ? -3 : 0;
#endif
}
