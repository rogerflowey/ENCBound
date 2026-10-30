/*
 * ENCBound restart - platform interface.
 *
 * The core runtime and the compiler pass depend only on this interface, never
 * on SDK-private structures. Exactly one backend translation unit
 * (sdk/platform_layout.c) binds it to the pinned Intel SGX SDK.
 */

#ifndef ENCBOUND_PLATFORM_H
#define ENCBOUND_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "encbound_regions.h"

/* Enclave-lifetime layout discovered and validated at bootstrap. */
typedef struct encbound_platform_config {
    uintptr_t enclave_base;
    uint64_t enclave_size;
    uintptr_t protected_heap_base;
    uint64_t protected_heap_size;
    uintptr_t trusted_heap_base;
    uint64_t trusted_heap_size;
    const encbound_region_t *regions;
    size_t region_count;
} encbound_platform_config_t;

/*
 * Discover, validate, and freeze the layout. Idempotent: the first call does
 * the work; later calls return the same result. Returns 0 on success.
 */
int encbound_platform_init(void);
bool encbound_platform_ready(void);
int encbound_platform_get_config(encbound_platform_config_t *out);

uintptr_t encbound_enclave_base(void);
uint64_t encbound_enclave_size(void);

size_t encbound_platform_region_count(void);
bool encbound_platform_region_at(size_t index, encbound_region_t *out);
bool encbound_platform_get_region(uint64_t offset, encbound_region_t *out);

/*
 * Classify [pointer, pointer+size): fully outside the enclave, or fully inside
 * exactly one region. Cross-edge and overflowing ranges are INVALID.
 */
encbound_classify_result_t encbound_platform_classify(
    const void *pointer, size_t size, encbound_region_t *out);
bool encbound_is_outside_enclave(const void *pointer, size_t size);

int encbound_platform_get_thread_ranges(uintptr_t *stack_base,
                                        uint64_t *stack_size,
                                        uintptr_t *tls_base, uint64_t *tls_size);

int encbound_platform_random(void *output, size_t size);
_Noreturn void encbound_abort(int code);

#endif /* ENCBOUND_PLATFORM_H */
