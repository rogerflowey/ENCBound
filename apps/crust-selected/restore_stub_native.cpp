/* Trusted native test driver only; no application/enclave execution claim. */
#include "restore_stub.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    assert(argc == 2);
    const uint8_t *data = nullptr;
    size_t size = 0;
    switch (argv[1][0]) {
    case 'n':
        break;
    case 'u': {
        size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        void *memory = mmap(nullptr, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(memory != MAP_FAILED);
        data = static_cast<const uint8_t *>(memory);
        size = page;
        break;
    }
    case 'p':
        data = reinterpret_cast<const uint8_t *>(UINT64_C(0x5000000000000001));
        size = SIZE_MAX;
        break;
    default:
        return 2;
    }
    crust_status_t (*volatile callback)(const uint8_t *, size_t) = ecall_restore_from_upgrade;
    callback(data, size);
    return 99; /* A completion callback must never return, including success. */
}
