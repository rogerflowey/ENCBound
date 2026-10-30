/*
 * ENCBound restart - runtime state, keyed MAC, and initialization.
 */

#include <stddef.h>
#include <stdint.h>

#include "encbound_common.h"
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "encbound_siphash.h"

#include "encbound_internal.h"

#ifdef ENCBOUND_AES_CMAC
#ifndef ENCBOUND_MAC27
#error "AES-CMAC selection is only valid in MAC27 builds"
#endif
#include "aes_cmac.h"
static encbound_cmac_context g_cmac;
#endif

static uint64_t g_k0;
static uint64_t g_k1;
static uintptr_t g_base;
static uint64_t g_size;
static int g_ready;
static int g_init_failed;

/* Compiler/linker-owned startup records. They are TRUSTED, never application
 * data. Cells begin as (radix << 59) + raw address and become capabilities.
 * Fixups describe known initializer fields; arbitrary application bytes are
 * never inspected to infer authority. Missing weak bounds mean no feature. */
extern uintptr_t __encbound_gcaps_start[] __attribute__((weak));
extern uintptr_t __encbound_gcaps_end[] __attribute__((weak));
typedef struct global_fixup {
    void *destination;
    const uintptr_t *entry;
    uint64_t addend;
} global_fixup_t;
extern const global_fixup_t __encbound_gfix_start[] __attribute__((weak));
extern const global_fixup_t __encbound_gfix_end[] __attribute__((weak));

static int trusted_global_span(uintptr_t start, uintptr_t end)
{
    encbound_region_t r;
    return start && end >= start &&
        (start == end || (encbound_platform_classify((void *)start, end-start, &r) ==
                         ENCBOUND_CLASSIFY_REGION && r.policy == ENCBOUND_REGION_TRUSTED));
}

static int global_entry_valid(const uintptr_t *entry)
{
    uintptr_t p=(uintptr_t)entry, a=(uintptr_t)__encbound_gcaps_start,
              b=(uintptr_t)__encbound_gcaps_end;
    return a && p>=a && p<b && (p-a)%sizeof(uintptr_t)==0;
}

static int initialize_globals(void)
{
    uintptr_t a=(uintptr_t)__encbound_gcaps_start, b=(uintptr_t)__encbound_gcaps_end;
    uintptr_t f=(uintptr_t)__encbound_gfix_start, e=(uintptr_t)__encbound_gfix_end;
    if (!a && !b && !f && !e) return ENCBOUND_OK;
    if (!trusted_global_span(a,b) || (b-a)%sizeof(uintptr_t) ||
        !trusted_global_span(f,e) || (e-f)%sizeof(global_fixup_t)) return ENCBOUND_ERR_STATE;
    /* Validate every slot before publishing any capability. */
    for (uintptr_t *p=__encbound_gcaps_start; p<__encbound_gcaps_end; ++p) {
        uint64_t r=*p >> ENCBOUND_RADIX_SHIFT;
        uintptr_t raw=*p & ((1ull << ENCBOUND_RADIX_SHIFT)-1);
        encbound_region_t region;
        if (r<ENCBOUND_RADIX_MIN || r>ENCBOUND_RADIX_MAX) return ENCBOUND_ERR_ENCODING;
        uint64_t size=1ull<<r;
        if (!raw || raw >= (1ull<<47) || (raw & (size-1)) ||
            raw<g_base || ((raw-g_base)&(size-1)) ||
            encbound_platform_classify((void *)raw,size,&region)!=ENCBOUND_CLASSIFY_REGION ||
            region.policy!=ENCBOUND_REGION_PROTECTED || region.domain!=ENCBOUND_DOMAIN_GLOBAL)
            return ENCBOUND_ERR_POLICY;
    }
    for (uintptr_t *p=__encbound_gcaps_start; p<__encbound_gcaps_end; ++p) {
        uint32_t r=*p >> ENCBOUND_RADIX_SHIFT;
        uintptr_t raw=*p & ((1ull<<ENCBOUND_RADIX_SHIFT)-1);
        *p=encbound_cap_encode(ENCBOUND_DOMAIN_GLOBAL,r,raw);
    }
    for (const global_fixup_t *p=__encbound_gfix_start; p<__encbound_gfix_end; ++p) {
        encbound_region_t region;
        if (!global_entry_valid(p->entry) ||
            encbound_platform_classify(p->destination,sizeof(uintptr_t),&region)!=ENCBOUND_CLASSIFY_REGION ||
            region.policy!=ENCBOUND_REGION_PROTECTED || region.domain!=ENCBOUND_DOMAIN_GLOBAL)
            return ENCBOUND_ERR_POLICY;
        uintptr_t value=*p->entry+p->addend;
        /* Packed records can contain unaligned pointer fields. */
        unsigned char *dst=p->destination;
        for (size_t i=0;i<sizeof(value);++i) dst[i]=(unsigned char)(value>>(8*i));
    }
    return ENCBOUND_OK;
}

uintptr_t encbound_global_cap(const uintptr_t *entry)
{
    if (!g_ready || !global_entry_valid(entry)) encbound_abort(ENCBOUND_ERR_POLICY);
    return *entry;
}

uint64_t encbound_key0(void)
{
    return g_k0;
}

uint64_t encbound_key1(void)
{
    return g_k1;
}

uintptr_t encbound_base(void)
{
    return g_base;
}

uint64_t encbound_size(void)
{
    return g_size;
}

int encbound_state_ready(void)
{
    return g_ready;
}

uint32_t encbound_tag_of(uintptr_t capability)
{
    return (uint32_t)((capability >> ENCBOUND_TAG_SHIFT) & ENCBOUND_TAG_MASK);
}

uint32_t encbound_radix_of(uintptr_t capability)
{
    return (uint32_t)(capability >> ENCBOUND_RADIX_SHIFT);
}

uint64_t encbound_mac27(uint32_t domain, uint32_t radix,
                        uint32_t slot_base_offset)
{
#ifdef ENCBOUND_AES_CMAC
    return encbound_cmac27(&g_cmac,(uint8_t)domain,(uint8_t)radix,slot_base_offset);
#else
    uint8_t message[6];
    message[0] = (uint8_t)domain;
    message[1] = (uint8_t)radix;
    message[2] = (uint8_t)(slot_base_offset & 0xffu);
    message[3] = (uint8_t)((slot_base_offset >> 8) & 0xffu);
    message[4] = (uint8_t)((slot_base_offset >> 16) & 0xffu);
    message[5] = (uint8_t)((slot_base_offset >> 24) & 0xffu);
    return encbound_siphash24_fixed6(g_k0, g_k1, message) & ENCBOUND_TAG_MASK;
#endif
}

static int init_common(uint64_t k0, uint64_t k1)
{
    encbound_platform_config_t config;

    if (encbound_platform_init() != 0 ||
        encbound_platform_get_config(&config) != 0) {
        g_ready = 0;
        return ENCBOUND_ERR_STATE;
    }
    if (encbound_heap_init(config.protected_heap_base,
                           config.protected_heap_size) != 0) {
        g_ready = 0;
        return ENCBOUND_ERR_STATE;
    }
#ifdef ENCBOUND_AES_CMAC
    encbound_cmac_init(&g_cmac,k0,k1);
#endif
    g_k0 = k0;
    g_k1 = k1;
    g_base = config.enclave_base;
    g_size = config.enclave_size;
    g_ready = 1;
    int globals_rc=initialize_globals();
    if (globals_rc!=ENCBOUND_OK) { g_ready=0; g_init_failed=1; return globals_rc; }
    return ENCBOUND_OK;
}

int encbound_runtime_init_with_key(uint64_t k0, uint64_t k1)
{
    /*
     * Deterministic test-key initialization must never overwrite a live
     * runtime: the key, allocator metadata and frozen region configuration are
     * for the enclave lifetime. Fresh test processes/instances can still use
     * deterministic keys before the first successful initialization.
     */
    if (g_ready || g_init_failed) {
        return ENCBOUND_ERR_STATE;
    }
    return init_common(k0, k1);
}

int encbound_runtime_init(void)
{
    uint8_t key[16];
    uint64_t k0;
    uint64_t k1;
    size_t i;

    /*
     * Production initialization is idempotent under the shared admission gate:
     * later sequential calls reuse the existing key, allocator and region
     * configuration instead of regenerating them. Global conversion failure
     * is terminal here too: converted cells must never be interpreted again as
     * raw startup records. The boundary gate records other startup failures.
     */
    if (g_init_failed) return ENCBOUND_ERR_STATE;
    if (g_ready) {
        return ENCBOUND_OK;
    }
    if (encbound_platform_random(key, sizeof(key)) != 0) {
        return ENCBOUND_ERR_STATE;
    }
    k0 = 0;
    k1 = 0;
    for (i = 0; i < 8; ++i) {
        k0 |= (uint64_t)key[i] << (8u * i);
        k1 |= (uint64_t)key[8 + i] << (8u * i);
    }
    return init_common(k0, k1);
}

int encbound_runtime_ready(void)
{
    return g_ready;
}
