/* Owner-authorized application adaptation for the Crust C01 prefix.
 * Keep the original dispatch-map entry, but exclude real restore completion.
 * Never inspect the buffer, mutate restore state or report successful restore.
 * Compile through the application driver in every matched profile.
 */
#include "restore_stub.h"
#include <stdlib.h>

extern "C" crust_status_t ecall_restore_from_upgrade(const uint8_t *, size_t)
{
    abort();
}
