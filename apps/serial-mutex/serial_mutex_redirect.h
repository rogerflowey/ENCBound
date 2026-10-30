/* Force-include ONLY for explicitly selected application translation units.
 * Never apply this header to SDK, runtime, bridge or unrelated application code.
 */
#ifndef ENCBOUND_APP_SERIAL_MUTEX_REDIRECT_H
#define ENCBOUND_APP_SERIAL_MUTEX_REDIRECT_H

#include "serial_mutex.h"

#define sgx_thread_mutex_lock app_serial_mutex_lock
#define sgx_thread_mutex_unlock app_serial_mutex_unlock

#endif
