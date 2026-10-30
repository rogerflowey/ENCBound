/* Compatibility names for the original Crust serial-mutex recipe. */
#include "../serial-mutex/serial_mutex.h"
#define crust_selected_serial_mutex_lock app_serial_mutex_lock
#define crust_selected_serial_mutex_unlock app_serial_mutex_unlock
