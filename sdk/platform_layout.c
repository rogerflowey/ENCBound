/*
 * ENCBound restart - Intel SGX SDK platform binding (step 2).
 *
 * This is the only translation unit that binds to SDK-private layout state.
 * It reads the pinned 2.26 tRTS structures, cross-checks the installed archive
 * at build time through _Static_asserts, validates the observed runtime values,
 * carves the protected arena from the SDK reserved region, and freezes the
 * region table that the runtime classifies against.
 *
 * Provenance (see evidence record and tools/check_sdk_pins.py):
 *   SDK 2.26.100.0, pinned internal headers from
 *   intel-sgx-simulation-2.26/common/inc/internal.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "encbound_platform.h"

#include "sgx_error.h"
#include "sgx_rsrv_mem_mngr.h"
#include "sgx_trts.h"

#include "global_data.h"
#include "thread_data.h"

/*
 * Explicit header/binary correspondence. These values were recomputed from the
 * pinned headers and cross-checked against the installed
 * libsgx_trts_sim.a's g_global_data object (1768 bytes). A header drift fails
 * the build instead of silently misreading SDK state.
 */
_Static_assert(sizeof(global_data_t) == 1768, "pinned global_data_t size");
_Static_assert(offsetof(global_data_t, enclave_size) == 8, "layout");
_Static_assert(offsetof(global_data_t, heap_offset) == 16, "layout");
_Static_assert(offsetof(global_data_t, heap_size) == 24, "layout");
_Static_assert(offsetof(global_data_t, rsrv_offset) == 32, "layout");
_Static_assert(offsetof(global_data_t, rsrv_size) == 40, "layout");
_Static_assert(offsetof(global_data_t, layout_entry_num) == 344, "layout");
_Static_assert(offsetof(global_data_t, layout_table) == 352, "layout");
_Static_assert(offsetof(global_data_t, enclave_image_address) == 1728,
               "layout");
_Static_assert(offsetof(global_data_t, elrange_start_address) == 1736,
               "layout");
_Static_assert(offsetof(global_data_t, elrange_size) == 1744, "layout");
_Static_assert(sizeof(thread_data_t) == 192, "pinned thread_data_t size");
_Static_assert(offsetof(thread_data_t, self_addr) == 0, "layout");
_Static_assert(offsetof(thread_data_t, stack_base_addr) == 16, "layout");
_Static_assert(offsetof(thread_data_t, stack_limit_addr) == 24, "layout");
_Static_assert(offsetof(thread_data_t, tls_addr) == 104, "layout");

#define ENCBOUND_PAGE_SIZE ((uint64_t)4096)
#define ENCBOUND_ARENA_SIZE ((uint64_t)0x01000000)          /* 16 MiB */
#define ENCBOUND_RESERVED_MIN_SIZE (2u * ENCBOUND_ARENA_SIZE) /* 32 MiB */
#define ENCBOUND_RADIX_MAX 30u
#define ENCBOUND_OFFSET_BITS 32u
#define ENCBOUND_ALIGNMENT (1ull << ENCBOUND_RADIX_MAX)     /* 1 GiB */

/* Initialization error categories (non-zero; stable enough for diagnostics). */
#define ENCBOUND_INIT_OK 0
#define ENCBOUND_INIT_ERR_BASE 1
#define ENCBOUND_INIT_ERR_IMAGE 2
#define ENCBOUND_INIT_ERR_HEAP 3
#define ENCBOUND_INIT_ERR_RESERVED 4
#define ENCBOUND_INIT_ERR_RSRV_INFO 5
#define ENCBOUND_INIT_ERR_ARENA 6
#define ENCBOUND_INIT_ERR_REGIONS 7
#define ENCBOUND_INIT_ERR_THREAD 8

static encbound_platform_config_t g_config;
static encbound_region_t g_regions[ENCBOUND_PLATFORM_CONFIG_MAX_REGIONS];
static size_t g_region_count;
static int g_ready;

/*
 * Application-owned COMPAT range (see sdk/enclave_sections.lds). The linker
 * defines these symbols inside the collected read-only .encbound.appdata
 * output section; weak so an app without the insert script still links, with
 * both symbols null (no COMPAT region).
 */
extern const unsigned char __encbound_appdata_start[] __attribute__((weak));
extern const unsigned char __encbound_appdata_end[] __attribute__((weak));

extern const unsigned char __encbound_apprelro_start[] __attribute__((weak));
extern const unsigned char __encbound_apprelro_end[] __attribute__((weak));
extern const unsigned char __encbound_apprw_start[] __attribute__((weak));
extern const unsigned char __encbound_apprw_end[] __attribute__((weak));
extern const unsigned char __encbound_appbss_start[] __attribute__((weak));
extern const unsigned char __encbound_appbss_end[] __attribute__((weak));
extern const unsigned char __encbound_globalrw_start[] __attribute__((weak));
extern const unsigned char __encbound_globalrw_end[] __attribute__((weak));
extern const unsigned char __encbound_globalbss_start[] __attribute__((weak));
extern const unsigned char __encbound_globalbss_end[] __attribute__((weak));

static bool add_region(uint64_t start, uint64_t size, uint32_t policy,
                       uint32_t domain)
{
    if (size == 0) {
        return true;
    }
    if (g_region_count >= ENCBOUND_PLATFORM_CONFIG_MAX_REGIONS) {
        return false;
    }
    if (start > UINT64_MAX - size) {
        return false;
    }
    g_regions[g_region_count].start_offset = start;
    g_regions[g_region_count].size = size;
    g_regions[g_region_count].policy = policy;
    g_regions[g_region_count].domain = domain;
    g_region_count++;
    return true;
}

static bool regions_sorted_disjoint(void)
{
    size_t i;
    for (i = 1; i < g_region_count; ++i) {
        uint64_t prev_end = g_regions[i - 1].start_offset +
                            g_regions[i - 1].size;
        if (prev_end > g_regions[i].start_offset) {
            return false;
        }
    }
    return true;
}

/*
 * Add the leading enclave-image region, splitting out the application-owned
 * COMPAT read-only range when one was linked in. The COMPAT slice is strictly
 * inside [0, heap_offset): the image's own code/data and the SDK heaps stay
 * TRUSTED, and no runtime/SDK bytes are reclassified.
 */
static bool add_image_regions(uint64_t base, uint64_t heap_offset)
{
    const unsigned char *bounds[][2] = {
        {__encbound_appdata_start, __encbound_appdata_end},
        {__encbound_apprelro_start, __encbound_apprelro_end},
        {__encbound_apprw_start, __encbound_apprw_end},
        {__encbound_appbss_start, __encbound_appbss_end},
        {__encbound_globalrw_start, __encbound_globalrw_end},
        {__encbound_globalbss_start, __encbound_globalbss_end}
    };
    uint64_t previous = 0;
    for (size_t i = 0; i < 6; ++i) {
        uint64_t start = (uintptr_t)bounds[i][0], end = (uintptr_t)bounds[i][1];
        if (!start && !end) continue;
        if (!start || !end || end < start || start < base || end - base > heap_offset)
            return false;
        if (start == end) continue;
        start -= base; end -= base;
        if (start < previous || (start & (ENCBOUND_PAGE_SIZE - 1))) return false;
        if (!add_region(previous, start - previous, ENCBOUND_REGION_TRUSTED, ENCBOUND_DOMAIN_NONE) ||
            !add_region(start, end - start, i<4 ? ENCBOUND_REGION_COMPAT : ENCBOUND_REGION_PROTECTED,
                        i<4 ? ENCBOUND_DOMAIN_NONE : ENCBOUND_DOMAIN_GLOBAL)) return false;
        previous = end;
    }
    return add_region(previous, heap_offset - previous, ENCBOUND_REGION_TRUSTED, ENCBOUND_DOMAIN_NONE);
}

int encbound_platform_init(void)
{
    uint64_t elrange_start;
    uint64_t elrange_size;
    uint64_t image;
    uint64_t heap_offset;
    uint64_t heap_size;
    uint64_t rsrv_offset;
    uint64_t rsrv_size;
    uint64_t reserved_base;
    uint64_t arena_base;
    uint64_t arena_offset;
    uint64_t arena_end;
    uint64_t rsrv_end;
    void *info_base = NULL;
    size_t info_size = 0;
    void *acquired;
    uintptr_t stack_base = 0;
    uintptr_t tls_base = 0;
    uint64_t stack_size = 0;
    uint64_t tls_size = 0;
    uint64_t stack_offset = 0;
    uint64_t tls_offset = 0;

    if (g_ready) {
        return ENCBOUND_INIT_OK;
    }

    elrange_start = g_global_data.elrange_start_address;
    elrange_size = g_global_data.elrange_size;
    image = g_global_data.enclave_image_address;
    heap_offset = g_global_data.heap_offset;
    heap_size = g_global_data.heap_size;
    rsrv_offset = g_global_data.rsrv_offset;
    rsrv_size = g_global_data.rsrv_size;

    if (elrange_start == 0 || elrange_size == 0 ||
        (elrange_start & (ENCBOUND_ALIGNMENT - 1)) != 0 ||
        (elrange_size & (elrange_size - 1)) != 0 ||
        elrange_size > ENCBOUND_ALIGNMENT ||
        elrange_size > (1ull << ENCBOUND_OFFSET_BITS)) {
        return ENCBOUND_INIT_ERR_BASE;
    }
    if (image != elrange_start) {
        return ENCBOUND_INIT_ERR_IMAGE;
    }
    if (heap_offset == 0 || heap_size == 0 ||
        heap_offset > elrange_size || heap_size > elrange_size - heap_offset) {
        return ENCBOUND_INIT_ERR_HEAP;
    }
    if (rsrv_size < ENCBOUND_RESERVED_MIN_SIZE ||
        rsrv_offset > elrange_size || rsrv_size > elrange_size - rsrv_offset) {
        return ENCBOUND_INIT_ERR_RESERVED;
    }
    rsrv_end = rsrv_offset + rsrv_size;

    reserved_base = elrange_start + rsrv_offset;
    arena_base = (reserved_base + ENCBOUND_ARENA_SIZE - 1) &
                 ~(ENCBOUND_ARENA_SIZE - 1);
    arena_offset = arena_base - elrange_start;
    arena_end = arena_offset + ENCBOUND_ARENA_SIZE;
    if (arena_base < reserved_base || arena_end > rsrv_end ||
        arena_offset < rsrv_offset ||
        (arena_base & (ENCBOUND_ARENA_SIZE - 1)) != 0) {
        return ENCBOUND_INIT_ERR_ARENA;
    }
    if (heap_offset + heap_size > rsrv_offset) {
        return ENCBOUND_INIT_ERR_ARENA;
    }

    /* Cross-check the SDK's own reserved-memory report against g_global_data. */
    if (sgx_get_rsrv_mem_info(&info_base, &info_size) != SGX_SUCCESS ||
        (uint64_t)(uintptr_t)info_base != reserved_base ||
        (uint64_t)info_size < ENCBOUND_RESERVED_MIN_SIZE) {
        return ENCBOUND_INIT_ERR_RSRV_INFO;
    }

    /* ENCBound owns [arena_base, arena_base + H) for the enclave lifetime. */
    acquired = sgx_alloc_rsrv_mem_ex((void *)(uintptr_t)arena_base,
                                     (size_t)ENCBOUND_ARENA_SIZE);
    if (acquired != (void *)(uintptr_t)arena_base) {
        return ENCBOUND_INIT_ERR_ARENA;
    }

    /*
     * The active TCS stack carries the instrumented application frames; its
     * usable extent is a PROTECTED stack region (whole region, but only
     * compiler-minted slots receive capabilities). SDK/runtime TLS stays
     * TRUSTED. Application COMPAT read-only globals are carved out of the image
     * region above when the linker collected them; unknown ranges stay DENIED.
     */
    if (encbound_platform_get_thread_ranges(&stack_base, &stack_size,
                                            &tls_base, &tls_size) != 0 ||
        stack_base < elrange_start || stack_size == 0 ||
        tls_base < elrange_start || tls_size == 0) {
        return ENCBOUND_INIT_ERR_THREAD;
    }
    stack_offset = (uint64_t)stack_base - elrange_start;
    tls_offset = (uint64_t)tls_base - elrange_start;
    if (stack_offset > elrange_size || stack_size > elrange_size - stack_offset ||
        tls_offset > elrange_size || tls_size > elrange_size - tls_offset) {
        return ENCBOUND_INIT_ERR_THREAD;
    }

    if (!add_image_regions(elrange_start, heap_offset) ||
        !add_region(heap_offset, heap_size, ENCBOUND_REGION_TRUSTED,
                    ENCBOUND_DOMAIN_NONE) ||
        !add_region(stack_offset, stack_size, ENCBOUND_REGION_PROTECTED,
                    ENCBOUND_DOMAIN_STACK) ||
        !add_region(tls_offset, tls_size, ENCBOUND_REGION_TRUSTED,
                    ENCBOUND_DOMAIN_NONE) ||
        !add_region(rsrv_offset, arena_offset - rsrv_offset,
                    ENCBOUND_REGION_TRUSTED, ENCBOUND_DOMAIN_NONE) ||
        !add_region(arena_offset, ENCBOUND_ARENA_SIZE,
                    ENCBOUND_REGION_PROTECTED, ENCBOUND_DOMAIN_HEAP) ||
        !add_region(arena_end, rsrv_end - arena_end, ENCBOUND_REGION_TRUSTED,
                    ENCBOUND_DOMAIN_NONE)) {
        g_region_count = 0;
        return ENCBOUND_INIT_ERR_REGIONS;
    }
    if (!regions_sorted_disjoint()) {
        g_region_count = 0;
        return ENCBOUND_INIT_ERR_REGIONS;
    }

    g_config.enclave_base = (uintptr_t)elrange_start;
    g_config.enclave_size = elrange_size;
    g_config.protected_heap_base = (uintptr_t)arena_base;
    g_config.protected_heap_size = ENCBOUND_ARENA_SIZE;
    g_config.trusted_heap_base = (uintptr_t)(elrange_start + heap_offset);
    g_config.trusted_heap_size = heap_size;
    g_config.regions = g_regions;
    g_config.region_count = g_region_count;
    g_ready = 1;
    return ENCBOUND_INIT_OK;
}

bool encbound_platform_ready(void)
{
    return g_ready != 0;
}

int encbound_platform_get_config(encbound_platform_config_t *out)
{
    if (!g_ready || out == NULL) {
        return ENCBOUND_INIT_ERR_BASE;
    }
    *out = g_config;
    return ENCBOUND_INIT_OK;
}

uintptr_t encbound_enclave_base(void)
{
    return g_config.enclave_base;
}

uint64_t encbound_enclave_size(void)
{
    return g_config.enclave_size;
}

size_t encbound_platform_region_count(void)
{
    return g_region_count;
}

bool encbound_platform_region_at(size_t index, encbound_region_t *out)
{
    if (!g_ready || index >= g_region_count || out == NULL) {
        return false;
    }
    *out = g_regions[index];
    return true;
}

bool encbound_platform_get_region(uint64_t offset, encbound_region_t *out)
{
    size_t i;
    if (!g_ready) {
        return false;
    }
    for (i = 0; i < g_region_count; ++i) {
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
    uint64_t start;
    uint64_t end;
    uint64_t enclave_end;
    size_t i;

    if (!g_ready) {
        return ENCBOUND_CLASSIFY_INVALID;
    }
    start = (uint64_t)(uintptr_t)pointer;
    if (start > UINT64_MAX - (uint64_t)size) {
        return ENCBOUND_CLASSIFY_INVALID;
    }
    end = start + (uint64_t)size;
    enclave_end = (uint64_t)g_config.enclave_base + g_config.enclave_size;

    if (end <= (uint64_t)g_config.enclave_base ||
        start >= enclave_end) {
        return ENCBOUND_CLASSIFY_OUTSIDE;
    }
    if (start < (uint64_t)g_config.enclave_base || end > enclave_end) {
        return ENCBOUND_CLASSIFY_INVALID;
    }

    {
        uint64_t off = start - (uint64_t)g_config.enclave_base;
        uint64_t off_end = end - (uint64_t)g_config.enclave_base;
        for (i = 0; i < g_region_count; ++i) {
            if (off >= g_regions[i].start_offset &&
                off_end <= g_regions[i].start_offset + g_regions[i].size) {
                if (out != NULL) {
                    *out = g_regions[i];
                }
                return ENCBOUND_CLASSIFY_REGION;
            }
        }
        if (out != NULL) {
            out->start_offset = off;
            out->size = off_end - off;
            out->policy = ENCBOUND_REGION_DENIED;
            out->domain = ENCBOUND_DOMAIN_NONE;
        }
        return ENCBOUND_CLASSIFY_REGION;
    }
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
    thread_data_t *td;
    uintptr_t s_low;
    uintptr_t s_high;
    uintptr_t t_low;
    uintptr_t t_high;

    if (stack_base == NULL || stack_size == NULL || tls_base == NULL ||
        tls_size == NULL) {
        return ENCBOUND_INIT_ERR_THREAD;
    }
    td = get_thread_data();
    if (td == NULL) {
        return ENCBOUND_INIT_ERR_THREAD;
    }
    s_low = (uintptr_t)td->stack_limit_addr;
    s_high = (uintptr_t)td->stack_base_addr;
    t_low = (uintptr_t)td->tls_addr;
    t_high = (uintptr_t)td->self_addr + sizeof(thread_data_t);
    if (s_high <= s_low || t_high <= t_low) {
        return ENCBOUND_INIT_ERR_THREAD;
    }
    *stack_base = s_low;
    *stack_size = (uint64_t)(s_high - s_low);
    *tls_base = t_low;
    *tls_size = (uint64_t)(t_high - t_low);
    return ENCBOUND_INIT_OK;
}

int encbound_platform_random(void *output, size_t size)
{
    if (size == 0) {
        return ENCBOUND_INIT_OK;
    }
    if (output == NULL) {
        return ENCBOUND_INIT_ERR_BASE;
    }
    if (sgx_read_rand((unsigned char *)output, size) != SGX_SUCCESS) {
        return ENCBOUND_INIT_ERR_BASE;
    }
    return ENCBOUND_INIT_OK;
}

_Noreturn void encbound_abort(int code)
{
    volatile int sink = code;
    (void)sink;
    __builtin_trap();
    for (;;) {
    }
}
