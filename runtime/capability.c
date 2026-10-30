/*
 * ENCBound restart - capability checks (tagged and untagged paths).
 *
 * A capability is a pointer-sized value. Bits 63..59 hold the radix (1..30 for
 * a tagged heap/stack capability; 0 or 31 mark untagged candidates), bits
 * 58..32 the MAC27 tag, and bits 31..0 the enclave offset.
 */

#include <stddef.h>
#include <stdint.h>

#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"

#include "encbound_internal.h"

uintptr_t encbound_cap_encode(uint32_t domain, uint32_t radix, uintptr_t slot)
{
    uint64_t offset;
    uint64_t capability;

    if (!encbound_state_ready() || radix < ENCBOUND_RADIX_MIN ||
        radix > ENCBOUND_RADIX_MAX || slot < encbound_base()) {
        return 0;
    }
    offset = (uint64_t)slot - (uint64_t)encbound_base();
    if (offset > ENCBOUND_OFFSET_MASK) {
        return 0;
    }
    capability = (uint64_t)radix << ENCBOUND_RADIX_SHIFT;
#ifdef ENCBOUND_MAC27
    {
        uint64_t slot_base = offset & ~((0x1ull << radix) - 1u);
        capability |=
            (uint64_t)encbound_mac27(domain, radix, (uint32_t)slot_base)
            << ENCBOUND_TAG_SHIFT;
    }
#endif
    capability |= offset & ENCBOUND_OFFSET_MASK;
    return (uintptr_t)capability;
}

int encbound_cap_to_heap_slot(uintptr_t capability, uintptr_t *slot_out,
                              uint32_t *radix_out)
{
    uint32_t radix = encbound_radix_of(capability);
    uint64_t offset = capability & ENCBOUND_OFFSET_MASK;
    uint64_t slot_size;
    uint64_t slot_base;
    encbound_region_t region;

    if (!encbound_state_ready() || slot_out == NULL || radix_out == NULL) {
        return ENCBOUND_ERR_STATE;
    }
    if (radix < ENCBOUND_RADIX_MIN || radix > ENCBOUND_RADIX_MAX) {
        return ENCBOUND_ERR_ENCODING;
    }
    slot_size = 0x1ull << radix;
    slot_base = offset & ~(slot_size - 1u);
    if (!encbound_platform_get_region(slot_base, &region)) {
        return ENCBOUND_ERR_POLICY;
    }
    if (region.policy != ENCBOUND_REGION_PROTECTED ||
        region.domain != ENCBOUND_DOMAIN_HEAP ||
        slot_base < region.start_offset ||
        slot_base + slot_size > region.start_offset + region.size) {
        return ENCBOUND_ERR_POLICY;
    }
    if (offset != slot_base) {
        return ENCBOUND_ERR_RANGE; /* interior or rebased pointer */
    }
#ifdef ENCBOUND_MAC27
    if ((uint64_t)encbound_tag_of(capability) !=
        encbound_mac27(ENCBOUND_DOMAIN_HEAP, radix, (uint32_t)slot_base)) {
        return ENCBOUND_ERR_TAG;
    }
#endif
    *slot_out = (uintptr_t)((uint64_t)encbound_base() + slot_base);
    *radix_out = radix;
    return ENCBOUND_OK;
}

static int check_untagged(uintptr_t address, size_t width, uintptr_t *raw)
{
    const uintptr_t low_canonical_limit = 0x1ull << 47;
    encbound_region_t region;
    encbound_classify_result_t result;

    /* The initial target uses low-48-bit canonical user addresses. NULL is not a
       valid application object, and the whole accessed range - not just the
       first byte - must stay canonical. width is nonzero here (encbound_check
       rejects zero). Use a subtraction-based bound: width is an unrestricted
       size_t, so `address + width - 1` can wrap; `width > limit - address`
       cannot once address < limit. */
    if (address == 0 || address >= low_canonical_limit ||
        width > low_canonical_limit - address) {
        return ENCBOUND_ERR_ENCODING;
    }
    result = encbound_platform_classify((const void *)address, width, &region);
    if (result == ENCBOUND_CLASSIFY_OUTSIDE) {
        *raw = address;
        return ENCBOUND_OK;
    }
    if (result == ENCBOUND_CLASSIFY_REGION &&
        region.policy == ENCBOUND_REGION_COMPAT) {
        *raw = address;
        return ENCBOUND_OK;
    }
    return ENCBOUND_ERR_POLICY;
}

static int check_tagged(uintptr_t capability, size_t width, uintptr_t *raw)
{
    uint32_t radix = encbound_radix_of(capability);
    uint64_t offset = capability & ENCBOUND_OFFSET_MASK;
    uint64_t slot_size;
    uint64_t slot_base;
    encbound_region_t region;
    uint32_t domain;

    if (radix < ENCBOUND_RADIX_MIN || radix > ENCBOUND_RADIX_MAX) {
        return ENCBOUND_ERR_ENCODING;
    }
    slot_size = 0x1ull << radix;
    slot_base = offset & ~(slot_size - 1u);
    if (!encbound_platform_get_region(slot_base, &region)) {
        return ENCBOUND_ERR_POLICY;
    }
    if (region.policy != ENCBOUND_REGION_PROTECTED ||
        slot_base < region.start_offset ||
        slot_base + slot_size > region.start_offset + region.size) {
        return ENCBOUND_ERR_POLICY;
    }
    domain = region.domain;
    if (domain != ENCBOUND_DOMAIN_HEAP && domain != ENCBOUND_DOMAIN_STACK && domain != ENCBOUND_DOMAIN_GLOBAL) {
        return ENCBOUND_ERR_DOMAIN;
    }
    if (width == 0 || width > slot_size ||
        (offset - slot_base) > slot_size - width) {
        return ENCBOUND_ERR_RANGE;
    }
#ifdef ENCBOUND_MAC27
    if ((uint64_t)encbound_tag_of(capability) !=
        encbound_mac27(domain, radix, (uint32_t)slot_base)) {
        return ENCBOUND_ERR_TAG;
    }
#endif
    *raw = (uintptr_t)((uint64_t)encbound_base() + offset);
    return ENCBOUND_OK;
}

int encbound_check(uintptr_t capability, size_t width, int kind, uintptr_t *raw)
{
    uintptr_t result = 0;
    int rc;
    uint32_t radix;

    if (raw == NULL || !encbound_state_ready()) {
        return ENCBOUND_ERR_STATE;
    }
    if (kind < ENCBOUND_ACCESS_READ || kind > ENCBOUND_ACCESS_READWRITE) {
        return ENCBOUND_ERR_STATE;
    }
    if (width == 0) {
        return ENCBOUND_ERR_RANGE;
    }
    radix = encbound_radix_of(capability);
    if (radix == 0 || radix == 0x1fu) {
        rc = check_untagged(capability, width, &result);
    } else {
        rc = check_tagged(capability, width, &result);
    }
    if (rc != ENCBOUND_OK) {
        return rc;
    }
    *raw = result;
    return ENCBOUND_OK;
}

uintptr_t encbound_require(uintptr_t capability, size_t width, int kind)
{
    uintptr_t raw = 0;
    int rc = encbound_check(capability, width, kind, &raw);
    if (rc != ENCBOUND_OK) {
        encbound_abort(rc);
    }
    return raw;
}

/* Compiler-private span validation. Failure is a zero token, not an abort:
 * speculative preparation of an unused/invalid pointer must not change an
 * empty loop or the first failing access. No application memory is read.
 * The validator confines the token to matching span_require calls. */
uintptr_t encbound_span_prepare(uintptr_t anchor)
{
    uint32_t radix = (uint32_t)(anchor >> ENCBOUND_RADIX_SHIFT);
    uintptr_t raw = 0;
    if (radix < ENCBOUND_RADIX_MIN || radix > ENCBOUND_RADIX_MAX) return 0;
    uint64_t size = UINT64_C(1) << radix;
    uintptr_t start = anchor & ~(size - 1);
    if (encbound_check(start, size, ENCBOUND_ACCESS_READWRITE, &raw) != ENCBOUND_OK)
        return 0;
    return raw;
}

/* Same-slot guard over FULL capability bits: a changed tag/radix, offset carry,
 * another slot, invalid token or straddle takes the original checked path.
 * The successful guard implies the same authenticated slot and complete range.
 * RADIX_ONLY fallback retains its original cross-slot/tag-bit behavior.
 * Raw span tokens are compiler-private values, never application arguments. */
uintptr_t encbound_span_require(uintptr_t capability, size_t width, int kind,
                                uintptr_t anchor, uintptr_t token)
{
    uint32_t radix = (uint32_t)(anchor >> ENCBOUND_RADIX_SHIFT);
    if (token && radix >= ENCBOUND_RADIX_MIN && radix <= ENCBOUND_RADIX_MAX &&
        kind >= ENCBOUND_ACCESS_READ && kind <= ENCBOUND_ACCESS_READWRITE) {
        uint64_t size = UINT64_C(1) << radix;
        uintptr_t start = anchor & ~(size - 1);
        uint64_t delta = capability - start;
        if (width && width <= size && delta <= size - width)
            return token + delta;
    }
    return encbound_require(capability, width, kind);
}

int encbound_check_extent(uintptr_t capability, uintptr_t *raw,
                          size_t *remaining_out)
{
    uint32_t radix;

    if (raw == NULL || remaining_out == NULL || !encbound_state_ready()) {
        return ENCBOUND_ERR_STATE;
    }
    radix = encbound_radix_of(capability);
    if (radix >= ENCBOUND_RADIX_MIN && radix <= ENCBOUND_RADIX_MAX) {
        uint64_t offset = capability & ENCBOUND_OFFSET_MASK;
        uint64_t slot_size = 0x1ull << radix;
        uint64_t slot_base = offset & ~(slot_size - 1u);
        encbound_region_t region;
        uint32_t domain;

        if (!encbound_platform_get_region(slot_base, &region)) {
            return ENCBOUND_ERR_POLICY;
        }
        if (region.policy != ENCBOUND_REGION_PROTECTED ||
            slot_base < region.start_offset ||
            slot_base + slot_size > region.start_offset + region.size) {
            return ENCBOUND_ERR_POLICY;
        }
        domain = region.domain;
        if (domain != ENCBOUND_DOMAIN_HEAP && domain != ENCBOUND_DOMAIN_STACK && domain != ENCBOUND_DOMAIN_GLOBAL) {
            return ENCBOUND_ERR_DOMAIN;
        }
#ifdef ENCBOUND_MAC27
        if ((uint64_t)encbound_tag_of(capability) !=
            encbound_mac27(domain, radix, (uint32_t)slot_base)) {
            return ENCBOUND_ERR_TAG;
        }
#endif
        *remaining_out = (size_t)(slot_size - (offset - slot_base));
        *raw = (uintptr_t)((uint64_t)encbound_base() + offset);
        return ENCBOUND_OK;
    }

    /* Untagged candidates only get a bounded extent from a COMPAT region. */
    {
        const uintptr_t low_canonical_limit = 0x1ull << 47;
        encbound_region_t region;
        uint64_t offset;

        if (capability == 0 || capability >= low_canonical_limit) {
            return ENCBOUND_ERR_ENCODING;
        }
        if (encbound_platform_classify((const void *)capability, 1, &region) !=
                ENCBOUND_CLASSIFY_REGION ||
            region.policy != ENCBOUND_REGION_COMPAT) {
            return ENCBOUND_ERR_POLICY;
        }
        offset = (uint64_t)capability - (uint64_t)encbound_base();
        *remaining_out =
            (size_t)(region.start_offset + region.size - offset);
        *raw = capability;
        return ENCBOUND_OK;
    }
}
