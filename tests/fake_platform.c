/*
 * ENCBound restart - declared fake platform for native runtime tests.
 *
 * Models a 64 MiB enclave over a host buffer with a PROTECTED heap arena, a
 * PROTECTED stack, a COMPAT region, and TRUSTED regions. Deterministic; no SGX.
 */

#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include "encbound_platform.h"

#define FAKE_SIZE 0x4000000ull /* 64 MiB */

static uint8_t g_memory[FAKE_SIZE] __attribute__((aligned(0x1000000)));

static const encbound_region_t g_regions[] = {
    { 0x000000ull, 0x100000ull, ENCBOUND_REGION_TRUSTED,
      ENCBOUND_DOMAIN_NONE },
    { 0x100000ull, 0x100000ull, ENCBOUND_REGION_PROTECTED,
      ENCBOUND_DOMAIN_STACK },
    { 0x200000ull, 0x010000ull, ENCBOUND_REGION_COMPAT, ENCBOUND_DOMAIN_NONE },
    { 0x300000ull, 0x100000ull, ENCBOUND_REGION_TRUSTED,
      ENCBOUND_DOMAIN_NONE },
    { 0x1000000ull, 0x1000000ull, ENCBOUND_REGION_PROTECTED,
      ENCBOUND_DOMAIN_HEAP },
    { 0x2000000ull, 0x100000ull, ENCBOUND_REGION_COMPAT, ENCBOUND_DOMAIN_NONE },
};
#define FAKE_REGION_COUNT (sizeof(g_regions) / sizeof(g_regions[0]))

int fake_abort_code;
jmp_buf fake_abort_env;
int fake_abort_active;

int encbound_platform_init(void)
{
    return 0;
}

int encbound_platform_get_config(encbound_platform_config_t *out)
{
    if (out == NULL) {
        return 1;
    }
    out->enclave_base = (uintptr_t)g_memory;
    out->enclave_size = FAKE_SIZE;
    out->protected_heap_base = (uintptr_t)g_memory + 0x1000000ull;
    out->protected_heap_size = 0x1000000ull;
    out->trusted_heap_base = (uintptr_t)g_memory + 0x300000ull;
    out->trusted_heap_size = 0x100000ull;
    out->regions = g_regions;
    out->region_count = FAKE_REGION_COUNT;
    return 0;
}

uintptr_t encbound_enclave_base(void)
{
    return (uintptr_t)g_memory;
}

uint64_t encbound_enclave_size(void)
{
    return FAKE_SIZE;
}

bool encbound_platform_get_region(uint64_t offset, encbound_region_t *out)
{
    size_t i;
    for (i = 0; i < FAKE_REGION_COUNT; ++i) {
        if (offset >= g_regions[i].start_offset &&
            offset - g_regions[i].start_offset < g_regions[i].size) {
            if (out != NULL) {
                *out = g_regions[i];
            }
            return true;
        }
    }
    return false;
}

encbound_classify_result_t encbound_platform_classify(
    const void *pointer, size_t size, encbound_region_t *out)
{
    uint64_t start = (uint64_t)(uintptr_t)pointer;
    uint64_t end;
    uint64_t base = (uint64_t)g_memory;
    uint64_t enclave_end = base + FAKE_SIZE;
    size_t i;

    if (size > UINT64_MAX || start > UINT64_MAX - (uint64_t)size) {
        return ENCBOUND_CLASSIFY_INVALID;
    }
    end = start + (uint64_t)size;
    if (end <= base || start >= enclave_end) {
        return ENCBOUND_CLASSIFY_OUTSIDE;
    }
    if (start < base || end > enclave_end) {
        return ENCBOUND_CLASSIFY_INVALID;
    }
    {
        uint64_t off = start - base;
        uint64_t off_end = end - base;
        for (i = 0; i < FAKE_REGION_COUNT; ++i) {
            if (off >= g_regions[i].start_offset &&
                off_end <= g_regions[i].start_offset + g_regions[i].size) {
                if (out != NULL) {
                    *out = g_regions[i];
                }
                return ENCBOUND_CLASSIFY_REGION;
            }
        }
    }
    if (out != NULL) {
        out->start_offset = start - base;
        out->size = end - start;
        out->policy = ENCBOUND_REGION_DENIED;
        out->domain = ENCBOUND_DOMAIN_NONE;
    }
    return ENCBOUND_CLASSIFY_REGION;
}

bool encbound_is_outside_enclave(const void *pointer, size_t size)
{
    return encbound_platform_classify(pointer, size, NULL) ==
           ENCBOUND_CLASSIFY_OUTSIDE;
}

int encbound_platform_get_thread_ranges(uintptr_t *stack_base,
                                        uint64_t *stack_size,
                                        uintptr_t *tls_base, uint64_t *tls_size)
{
    if (stack_base) {
        *stack_base = (uintptr_t)g_memory + 0x100000ull;
    }
    if (stack_size) {
        *stack_size = 0x100000ull;
    }
    if (tls_base) {
        *tls_base = (uintptr_t)g_memory + 0x200000ull;
    }
    if (tls_size) {
        *tls_size = 0x1000ull;
    }
    return 0;
}

int encbound_platform_random(void *output, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) {
        ((uint8_t *)output)[i] = (uint8_t)(0x30u + i);
    }
    return 0;
}

_Noreturn void encbound_abort(int code)
{
    fake_abort_code = code;
    if (fake_abort_active) {
        longjmp(fake_abort_env, 1);
    }
    for (;;) {
    }
}
