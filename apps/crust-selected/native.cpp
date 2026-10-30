/* Native test driver, outside the application pass. No SGX isolation claim.
 * The original SafeLock methods and serial stubs are separately compiled using
 * the application driver; protected methods receive a real heap capability.
 */
#include <assert.h>
#include <new>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "SafeLock.h"
#include "../serial-mutex/serial_mutex.h"
#include "encbound_runtime.h"
extern "C" {
#include "boundary_support.h"
}

static unsigned sdk_locks;
static unsigned sdk_unlocks;

/* SDK-shaped spies belong only to this native driver. A redirect accidentally
 * applied to this translation unit would collide with the private stub symbols.
 */
extern "C" int sgx_thread_mutex_lock(sgx_thread_mutex_t *)
{
    ++sdk_locks;
    return 91;
}

extern "C" int sgx_thread_mutex_unlock(sgx_thread_mutex_t *)
{
    ++sdk_unlocks;
    return 92;
}

int main()
{
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void *unreadable = mmap(nullptr, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(unreadable != MAP_FAILED);
    sgx_thread_mutex_t mutex;
    memset(&mutex, 0xa5, sizeof(mutex));
    unsigned char before[sizeof(mutex)];
    memcpy(before, &mutex, sizeof(mutex));

    /* Stub calls must perform no access, including through poisoned fields,
     * unmapped encodings and a real unreadable page. This is not mutex validation.
     */
    sgx_thread_mutex_t *arguments[] = {
        &mutex, nullptr, static_cast<sgx_thread_mutex_t *>(unreadable),
        reinterpret_cast<sgx_thread_mutex_t *>(UINT64_C(0x5000000000000001))
    };
    for (auto argument : arguments) {
        assert(app_serial_mutex_lock(argument) == 0);
        assert(app_serial_mutex_unlock(argument) == 0);
    }
    assert(sgx_thread_mutex_lock(&mutex) == 91);
    assert(sgx_thread_mutex_unlock(&mutex) == 92);

#ifdef ENCBOUND_PROTECTED
    assert(encbound_runtime_init_with_key(11, 22) == 0);
    void *object_cap = encbound_malloc(sizeof(SafeLock));
    assert(object_cap != nullptr);
    void *object_raw = reinterpret_cast<void *>(encbound_require(
        reinterpret_cast<uintptr_t>(object_cap), sizeof(SafeLock), ENCBOUND_ACCESS_READWRITE));
#else
    alignas(SafeLock) unsigned char storage[sizeof(SafeLock)];
    void *object_cap = storage;
    void *object_raw = storage;
#endif
    for (unsigned i = 0; i < 64; ++i) {
        assert(encbound_boundary_admit() == 0);
        assert(encbound_boundary_admit() != 0);
        assert(encbound_boundary_initialize() == 0);
        new (object_raw) SafeLock(mutex);
        auto object = static_cast<SafeLock *>(object_cap);
        object->lock();
        object->lock();
        if (i & 1) {
            object->unlock();
            object->lock();
        }
        object->~SafeLock();
        encbound_boundary_release();
        if (sdk_locks != 1 || sdk_unlocks != 1) {
            fputs("RAW SDK MUTEX CALL ESCAPED APPLICATION REDIRECT\n", stderr);
            return 42;
        }
        assert(memcmp(before, &mutex, sizeof(mutex)) == 0);
    }
#ifdef ENCBOUND_PROTECTED
    encbound_free(object_cap);
#endif
    assert(munmap(unreadable, page) == 0);
    puts("CRUST SERIAL MUTEX NATIVE PASS: 64 gated sequences, 64 nested rejections, SDK symbols separate");
}
