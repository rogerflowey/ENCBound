/* TRUSTED TEST ONLY. No raw address/key is exported or admitted to app calls. */
#include <stdint.h>
#include <stdlib.h>
#include "probe_t.h"
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "encbound_internal.h"

int startup_work(void);
uintptr_t startup_heap_bits(void), startup_global_bits(void);
static unsigned order;
static uintptr_t saved_heap, saved_global;
static void first_observer(void), second_observer(void);
/* Same priority as the bootstrap: the final-image audit must catch bad ties. */
__attribute__((used,section(".init_array.00000")))
static void (*const first_entry)(void) = first_observer;
__attribute__((used,section(".init_array.00200")))
static void (*const second_entry)(void) = second_observer;
#ifdef ENCBOUND_PROTECTED
static uint64_t saved_k0, saved_k1;
#endif

static void stop(void) { abort(); }

static void first_observer(void)
{
    if (order++) stop();
#ifdef ENCBOUND_PROTECTED
    if (!encbound_runtime_ready()) stop();
    saved_k0 = encbound_key0();
    saved_k1 = encbound_key1();
#endif
    if (startup_work() != 42) stop();
    saved_heap = startup_heap_bits();
    saved_global = startup_global_bits();
#ifdef ENCBOUND_PROTECTED
    uintptr_t raw;
    encbound_region_t region;
    if (encbound_check(saved_heap, 32, ENCBOUND_ACCESS_READ, &raw) ||
        encbound_platform_classify((void *)raw, 32, &region) != ENCBOUND_CLASSIFY_REGION ||
        region.policy != ENCBOUND_REGION_PROTECTED || region.domain != ENCBOUND_DOMAIN_HEAP) stop();
    if (encbound_check(saved_global, 4, ENCBOUND_ACCESS_READ, &raw) ||
        encbound_platform_classify((void *)raw, 4, &region) != ENCBOUND_CLASSIFY_REGION ||
        region.policy != ENCBOUND_REGION_PROTECTED || region.domain != ENCBOUND_DOMAIN_GLOBAL) stop();
    if (encbound_check((uintptr_t)&first_entry, sizeof(first_entry), ENCBOUND_ACCESS_READ, &raw)
        != ENCBOUND_ERR_POLICY) stop();
#endif
    if (startup_notify() != SGX_SUCCESS) stop();
}

static void second_observer(void) { if (order++ != 1) stop(); }

int inspect(void)
{
    if (order != 2 || startup_heap_bits() != saved_heap ||
        startup_global_bits() != saved_global) return -1;
#ifdef ENCBOUND_PROTECTED
    uintptr_t raw;
    if (!encbound_runtime_ready() || encbound_key0() != saved_k0 ||
        encbound_key1() != saved_k1 ||
        encbound_check(saved_heap, 32, ENCBOUND_ACCESS_READ, &raw) ||
        encbound_check(saved_global, 4, ENCBOUND_ACCESS_READ, &raw)) return -2;
#endif
    return 0;
}
