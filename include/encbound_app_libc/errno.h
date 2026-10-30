/* Application-only overlay: retain the selected libc's error constants and
 * bind its errno interface to the serial ENCBound application environment.
 * Never put this directory on host or trusted SDK compilation search paths. */
#ifndef ENCBOUND_APP_LIBC_ERRNO_H
#define ENCBOUND_APP_LIBC_ERRNO_H

#include_next <errno.h>
#include "encbound_app_errno.h"

#undef errno
#define errno (*__encbound_app_errno_location())
/* Supported SDK and system-header accessors share this same environment.
 * Define these after the underlying header's declarations, avoiding changes
 * to their libc-specific C++ exception specifications or attributes. */
#undef __errno
#undef __errno_location
#define __errno __encbound_app_errno_location
#define __errno_location __encbound_app_errno_location

#endif
