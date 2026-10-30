/* Application-only Itanium lifecycle adapters. The SDK owns scheduling and its
 * registry. Callback/object bits pass unchanged; SDK tokens never enter app IR.
 * Guards are decoded only after a complete eight-byte read/write check.
 * This profile remains serial. The optional EH mode uses guard_abort for
 * constructor failure/retry; application threading remains unsupported. */
#include <stdint.h>
#include "encbound_runtime.h"

extern void *__dso_handle;
extern int __cxa_atexit(void (*callback)(void *), void *object, void *dso);
extern int __cxa_guard_acquire(volatile int64_t *guard);
extern void __cxa_guard_release(int64_t *guard);
extern void __cxa_guard_abort(int64_t *guard);

int encbound_cxx_atexit(void (*callback)(void *), void *object)
{
    return __cxa_atexit(callback, object, __dso_handle);
}

static int64_t *checked_guard(void *guard)
{
    return (int64_t *)encbound_require((uintptr_t)guard, sizeof(int64_t), ENCBOUND_ACCESS_READWRITE);
}
int encbound_cxx_guard_acquire(void *guard) { return __cxa_guard_acquire(checked_guard(guard)); }
void encbound_cxx_guard_release(void *guard) { __cxa_guard_release(checked_guard(guard)); }
void encbound_cxx_guard_abort(void *guard) { __cxa_guard_abort(checked_guard(guard)); }
