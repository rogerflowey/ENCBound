/* Selected incomplete-transfer workload only; restore completion is terminal. */
#ifndef CRUST_SELECTED_RESTORE_STUB_H
#define CRUST_SELECTED_RESTORE_STUB_H

#include <stddef.h>
#include <stdint.h>
#include "CrustStatus.h"

#ifdef __cplusplus
extern "C" {
#endif
crust_status_t ecall_restore_from_upgrade(const uint8_t *data, size_t data_size);
#ifdef __cplusplus
}
#endif

#endif
