/*
 * ENCBound restart - runtime-internal interface (not for application code).
 */

#ifndef ENCBOUND_INTERNAL_H
#define ENCBOUND_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

uint64_t encbound_key0(void);
uint64_t encbound_key1(void);
uintptr_t encbound_base(void);
uint64_t encbound_size(void);
int encbound_state_ready(void);

/* tag = SipHash-2-4(key, {domain,radix,LE32(slot_base)}) & 0x07ffffff */
uint64_t encbound_mac27(uint32_t domain, uint32_t radix,
                        uint32_t slot_base_offset);
uint32_t encbound_tag_of(uintptr_t capability);
uint32_t encbound_radix_of(uintptr_t capability);

/* Build a capability for an absolute slot address in `domain`. */
uintptr_t encbound_cap_encode(uint32_t domain, uint32_t radix, uintptr_t slot);
/* Authenticate a heap capability and require its exact slot base. */
int encbound_cap_to_heap_slot(uintptr_t capability, uintptr_t *slot_out,
                              uint32_t *radix_out);
int encbound_free_checked(void *capability);

/* Heap arena allocator (trusted bookkeeping). */
int encbound_heap_init(uintptr_t base, uint64_t size);
int encbound_heap_alloc(size_t size, uintptr_t *slot_out, uint32_t *radix_out);
int encbound_heap_alloc_aligned(size_t size, size_t alignment, uintptr_t *slot_out, uint32_t *radix_out);
int encbound_heap_free(uintptr_t slot, uint32_t radix);
int encbound_heap_requested(uintptr_t slot, uint32_t radix, size_t *size_out);

#endif /* ENCBOUND_INTERNAL_H */
