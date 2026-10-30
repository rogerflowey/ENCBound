/* Serial application workloads only; see README.md for the required gate. */
#ifndef ENCBOUND_APP_SERIAL_MUTEX_H
#define ENCBOUND_APP_SERIAL_MUTEX_H

#include <sgx_thread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Synchronization is omitted. The pointer is neither read nor dereferenced. */
int app_serial_mutex_lock(sgx_thread_mutex_t *mutex);
int app_serial_mutex_unlock(sgx_thread_mutex_t *mutex);

#ifdef __cplusplus
}
#endif

#endif
