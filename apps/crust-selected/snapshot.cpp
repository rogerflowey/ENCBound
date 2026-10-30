/* Application-owned test observation of the selected incomplete-transfer pool.
 * Only copies bytes for the finite known-size sessions; exports no pointers.
 */
#include <map>
#include <stdint.h>
#include <string.h>

extern std::map<uint32_t, uint8_t *> g_ecall_buffer_pool;

extern "C" int crust_selected_snapshot(uint32_t key, uint8_t *output, size_t bytes)
{
    auto item = g_ecall_buffer_pool.find(key);
    if (item == g_ecall_buffer_pool.end())
        return -1;
    memcpy(output, item->second, bytes);
    return static_cast<int>(g_ecall_buffer_pool.size());
}
