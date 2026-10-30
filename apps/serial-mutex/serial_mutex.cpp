/* Shared application adaptation for explicitly selected serial workloads.
 * Compile as application code in every profile. SDK mutex symbols stay intact.
 */
#include "serial_mutex.h"

extern "C" int app_serial_mutex_lock(sgx_thread_mutex_t *)
{
    return 0;
}

extern "C" int app_serial_mutex_unlock(sgx_thread_mutex_t *)
{
    return 0;
}
