/*
 * ENCBound restart - shared trusted boundary support (docs/legacy/steps/09-original-api-and-sessions.md).
 *
 * See sdk/boundary_support.h. Compiled trusted and uninstrumented; in protected
 * profiles it forwards to the checked runtime allocator and capability checks.
 * The admission gate is a single trusted global because one enclave instance
 * serves a serial sequence of application invocations.
 */

#include <stddef.h>
#include <stdint.h>

#include "boundary_support.h"

#ifdef ENCBOUND_PROTECTED
#include "encbound_platform.h"
#include "encbound_runtime.h"
#else
#include <stdlib.h>
#endif

/* Session gate: idle, active, or terminal. */
#define ENCBOUND_GATE_IDLE 0
#define ENCBOUND_GATE_ACTIVE 1
#define ENCBOUND_GATE_FAILED 2

static int encbound_boundary_state;

/* Initialize-once state, separate from whether a call is active. */
#ifdef ENCBOUND_PROTECTED
static int encbound_boundary_initialized;
static int encbound_boundary_init_failed;
#endif

int encbound_boundary_admit(void)
{
    int expected = ENCBOUND_GATE_IDLE;
    if (!__atomic_compare_exchange_n(&encbound_boundary_state, &expected,
                                     ENCBOUND_GATE_ACTIVE, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return -1;
    }
    return 0;
}

void encbound_boundary_release(void)
{
    /* Only an active call releases; a terminal session stays terminal. */
    int expected = ENCBOUND_GATE_ACTIVE;
    __atomic_compare_exchange_n(&encbound_boundary_state, &expected,
                                ENCBOUND_GATE_IDLE, 0,
                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

void encbound_boundary_fail(void)
{
    __atomic_store_n(&encbound_boundary_state, ENCBOUND_GATE_FAILED,
                     __ATOMIC_RELEASE);
}

int encbound_boundary_initialize(void)
{
#ifdef ENCBOUND_PROTECTED
    if (encbound_boundary_init_failed) {
        return -1;
    }
    if (encbound_boundary_initialized) {
        return 0;
    }
    if (encbound_platform_init() != 0 || encbound_runtime_init() != 0) {
        encbound_boundary_init_failed = 1;
        return -1;
    }
    encbound_boundary_initialized = 1;
#endif
    return 0;
}

#ifdef ENCBOUND_PROTECTED

void *encbound_boundary_alloc(size_t size)
{
    return encbound_malloc(size);
}

void encbound_boundary_free(void *capability)
{
    if (capability != NULL) {
        encbound_free(capability);
    }
}

uint8_t *encbound_boundary_write(void *capability, size_t width)
{
    return (uint8_t *)encbound_require((uintptr_t)capability, width,
                                       ENCBOUND_ACCESS_WRITE);
}

const uint8_t *encbound_boundary_read(const void *capability, size_t width)
{
    return (const uint8_t *)encbound_require((uintptr_t)capability, width,
                                             ENCBOUND_ACCESS_READ);
}

#else

void *encbound_boundary_alloc(size_t size)
{
    return malloc(size);
}

void encbound_boundary_free(void *pointer)
{
    free(pointer);
}

uint8_t *encbound_boundary_write(void *pointer, size_t width)
{
    (void)width;
    return (uint8_t *)pointer;
}

const uint8_t *encbound_boundary_read(const void *pointer, size_t width)
{
    (void)width;
    return (const uint8_t *)pointer;
}

#endif /* ENCBOUND_PROTECTED */

size_t encbound_boundary_strnlen(const char *pointer, size_t cap)
{
    size_t i;
    if (pointer == NULL) {
        return (size_t)-1;
    }
    for (i = 0; i < cap; ++i) {
        if (pointer[i] == '\0') {
            return i;
        }
    }
    return (size_t)-1;
}
