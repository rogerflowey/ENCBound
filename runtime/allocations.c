/*
 * ENCBound restart - application allocation API and compiler-only stack mint.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"

#include "encbound_internal.h"

static uint32_t slot_order(size_t size)
{
    uint32_t order = 0;
    size_t v = size > 1 ? size - 1 : 1;
    while (v > 0) {
        order++;
        v >>= 1;
    }
    return order;
}

static void *heap_capability(uint32_t radix, uintptr_t slot)
{
    return (void *)encbound_cap_encode(ENCBOUND_DOMAIN_HEAP, radix, slot);
}

void *encbound_alloc_aligned(size_t size, size_t alignment)
{
    uintptr_t slot = 0;
    uint32_t radix = 0;
    void *capability;

    if (size == 0 || !encbound_runtime_ready()) {
        return NULL;
    }
    if (encbound_heap_alloc_aligned(size, alignment, &slot, &radix) != ENCBOUND_OK) {
        return NULL;
    }
    capability = heap_capability(radix, slot);
    if (capability == NULL) {
        (void)encbound_heap_free(slot, radix);
        return NULL;
    }
    return capability;
}

void *encbound_malloc(size_t size)
{
    return encbound_alloc_aligned(size, 1);
}

void *encbound_calloc(size_t count, size_t size)
{
    size_t total;
    uintptr_t slot = 0;
    uint32_t radix = 0;
    void *capability;

    if (count == 0 || size == 0 || !encbound_runtime_ready()) {
        return NULL;
    }
    if (count > (size_t)-1 / size) {
        return NULL;
    }
    total = count * size;
    if (encbound_heap_alloc(total, &slot, &radix) != ENCBOUND_OK) {
        return NULL;
    }
    memset((void *)slot, 0, total);
    capability = heap_capability(radix, slot);
    if (capability == NULL) {
        (void)encbound_heap_free(slot, radix);
        return NULL;
    }
    return capability;
}

int encbound_free_checked(void *capability)
{
    uintptr_t slot = 0;
    uint32_t radix = 0;
    int rc;

    if (capability == NULL) {
        return ENCBOUND_OK;
    }
    rc = encbound_cap_to_heap_slot((uintptr_t)capability, &slot, &radix);
    if (rc != ENCBOUND_OK) {
        return rc;
    }
    return encbound_heap_free(slot, radix);
}

void encbound_free(void *capability)
{
    int rc = encbound_free_checked(capability);
    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
}

void *encbound_realloc(void *capability, size_t size)
{
    uintptr_t old_slot = 0;
    uintptr_t new_slot = 0;
    uint32_t old_radix = 0;
    uint32_t new_radix = 0;
    size_t old_requested = 0;
    size_t copy;
    void *new_capability;

    if (capability == NULL) {
        return encbound_malloc(size);
    }
    if (size == 0) {
        encbound_free(capability);
        return NULL;
    }
    if (encbound_cap_to_heap_slot((uintptr_t)capability, &old_slot,
                                  &old_radix) != ENCBOUND_OK ||
        encbound_heap_requested(old_slot, old_radix, &old_requested) !=
            ENCBOUND_OK) {
        encbound_abort(ENCBOUND_ERR_OWNERSHIP);
    }
    if (encbound_heap_alloc(size, &new_slot, &new_radix) != ENCBOUND_OK) {
        return NULL; /* preserve the old allocation */
    }
    copy = old_requested < size ? old_requested : size;
    memcpy((void *)new_slot, (const void *)old_slot, copy);
    new_capability = heap_capability(new_radix, new_slot);
    if (new_capability == NULL) {
        (void)encbound_heap_free(new_slot, new_radix);
        return NULL;
    }
    (void)encbound_heap_free(old_slot, old_radix);
    return new_capability;
}

uintptr_t encbound_stack_mint(void *slot_address, size_t slot_size)
{
    void *capability = NULL;
    int rc = encbound_stack_slot(slot_address, slot_size, &capability);
    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
    return (uintptr_t)capability;
}

/* Room below a dynamic reservation for the ordinary ABI, mint/check helpers
 * and alignment. This does not bound arbitrary application callees/recursion. */
#define DYNAMIC_STACK_HEADROOM ((size_t)16384)

size_t encbound_stack_product(size_t a, size_t b)
{
    if (a == 0 || b == 0 || a > ((size_t)1 << ENCBOUND_RADIX_MAX) / b)
        encbound_abort(ENCBOUND_ERR_ALLOC);
    return a * b;
}

size_t encbound_stack_prepare(void *stack_pointer, size_t count,
                              size_t element_size, size_t alignment)
{
    uintptr_t sp = (uintptr_t)stack_pointer;
    uint64_t offset;
    size_t bytes, need, slot = 16;
    encbound_region_t region;

    if (!encbound_runtime_ready() || count == 0 || element_size == 0 ||
        count > ((size_t)1 << ENCBOUND_RADIX_MAX) / element_size ||
        alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        alignment > ((size_t)1 << ENCBOUND_RADIX_MAX))
        encbound_abort(ENCBOUND_ERR_ALLOC);
    bytes = count * element_size;
    need = bytes > alignment ? bytes : alignment;
    while (slot < need) slot <<= 1;
    if (sp < encbound_base()) encbound_abort(ENCBOUND_ERR_POLICY);
    offset = (uint64_t)sp - encbound_base();
    /* Classify sp-1 too: SP may be precisely the upper region boundary. */
    if (offset == 0 || !encbound_platform_get_region(offset - 1, &region) ||
        region.policy != ENCBOUND_REGION_PROTECTED ||
        region.domain != ENCBOUND_DOMAIN_STACK || offset < region.start_offset ||
        offset - region.start_offset > region.size)
        encbound_abort(ENCBOUND_ERR_POLICY);
    if (2 * slot + DYNAMIC_STACK_HEADROOM > offset - region.start_offset)
        encbound_abort(ENCBOUND_ERR_ALLOC);
    return slot;
}

uintptr_t encbound_stack_mint_dynamic(void *reservation, size_t slot_size)
{
    uintptr_t raw = (uintptr_t)reservation, aligned;
    encbound_region_t region;
    uint64_t offset;
    if (slot_size < 16 || slot_size > ((size_t)1 << ENCBOUND_RADIX_MAX) ||
        (slot_size & (slot_size - 1)) != 0 || raw < encbound_base())
        encbound_abort(ENCBOUND_ERR_ALLOC);
    offset = (uint64_t)raw - encbound_base();
    if (!encbound_platform_get_region(offset, &region) ||
        region.policy != ENCBOUND_REGION_PROTECTED ||
        region.domain != ENCBOUND_DOMAIN_STACK || offset < region.start_offset ||
        offset - region.start_offset > region.size ||
        2 * slot_size > region.size - (offset - region.start_offset) ||
        raw > UINTPTR_MAX - (slot_size - 1))
        encbound_abort(ENCBOUND_ERR_POLICY);
    aligned = (raw + slot_size - 1) & ~(uintptr_t)(slot_size - 1);
    return encbound_stack_mint((void *)aligned, slot_size);
}

int encbound_stack_slot(void *slot_address, size_t slot_size,
                        void **capability_out)
{
    uintptr_t address = (uintptr_t)slot_address;
    uint64_t offset;
    uint64_t slot_size64 = (uint64_t)slot_size;
    uint32_t radix;
    encbound_region_t region;

    if (!encbound_runtime_ready() || slot_address == NULL ||
        capability_out == NULL || slot_size == 0 ||
        (slot_size & (slot_size - 1)) != 0 || address < encbound_base()) {
        return ENCBOUND_ERR_ALLOC;
    }
    if ((address & (slot_size - 1)) != 0) {
        return ENCBOUND_ERR_ALLOC;
    }
    offset = (uint64_t)address - (uint64_t)encbound_base();
    radix = slot_order(slot_size);
    if (radix < ENCBOUND_RADIX_MIN || radix > ENCBOUND_RADIX_MAX) {
        return ENCBOUND_ERR_ALLOC;
    }
    if (!encbound_platform_get_region(offset, &region)) {
        return ENCBOUND_ERR_POLICY;
    }
    if (region.policy != ENCBOUND_REGION_PROTECTED ||
        region.domain != ENCBOUND_DOMAIN_STACK ||
        offset < region.start_offset ||
        offset + slot_size64 > region.start_offset + region.size) {
        return ENCBOUND_ERR_POLICY;
    }
    /* Clear the whole rounded slot before exposing it, including padding. */
    memset((void *)address, 0, slot_size);
    *capability_out = (void *)encbound_cap_encode(ENCBOUND_DOMAIN_STACK, radix,
                                                  address);
    if (*capability_out == NULL) {
        return ENCBOUND_ERR_STATE;
    }
    return ENCBOUND_OK;
}
