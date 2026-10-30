/* Original ENCBound application support. Compile through encbound-cc.sh and
 * application data placement, once per enclave application/library closure. */
#include "encbound_app_errno.h"

static int application_errno;

int *__encbound_app_errno_location(void)
{
    return &application_errno;
}

void __encbound_app_errno_store(int value)
{
    application_errno = value;
}
