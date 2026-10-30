/* Sparse allocator regressions against the native fake platform. Raw malloc
 * wrapping injects trusted-metadata failures; no production test hooks. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encbound_common.h"
#include "encbound_internal.h"
#include "encbound_runtime.h"
#include "encbound_platform.h"

#define HEAP_SIZE (1u << 24)
#define MANY 8192u

/* Keep the returned metadata pointer maximally aligned. */
typedef union metadata_header {
    max_align_t alignment;
    size_t bytes;
} metadata_header_t;

static size_t attempts, fail_at, live_pairs, live_bytes, peak_bytes;
static uintptr_t arena;
static void *caps[MANY];
static unsigned char occupied[HEAP_SIZE / 16];

void *__real_malloc(size_t);
void __real_free(void *);
void *__wrap_malloc(size_t n)
{
    metadata_header_t *p;
    attempts++;
    if (fail_at && attempts == fail_at) return NULL;
    p = __real_malloc(sizeof(*p) + n);
    assert(p != NULL);
    p->bytes = n;
    live_pairs++;
    live_bytes += n;
    if (peak_bytes < live_bytes) peak_bytes = live_bytes;
    return p + 1;
}
void __wrap_free(void *p)
{
    metadata_header_t *h;
    if (!p) return;
    h = (metadata_header_t *)p - 1;
    assert(live_pairs && live_bytes >= h->bytes);
    live_pairs--;
    live_bytes -= h->bytes;
    __real_free(h);
}

static void fail_on(size_t call)
{
    attempts = 0;
    fail_at = call;
}

static void empty_again(void)
{
    uintptr_t slot = 0;
    uint32_t radix = 0;
    assert(live_pairs == 0 && live_bytes == 0);
    /* Even total metadata exhaustion must allow the already represented root. */
    fail_on(1);
    assert(encbound_heap_alloc(HEAP_SIZE, &slot, &radix) == ENCBOUND_OK);
    assert(slot == arena && radix == 24 && attempts == 0);
    assert(encbound_heap_free(slot, radix) == ENCBOUND_OK);
    fail_on(0);
}

static void initialization(void)
{
    uintptr_t slot = 0;
    uint32_t radix = 0;
    encbound_platform_config_t config;
    assert(encbound_heap_alloc(16, &slot, &radix) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_free(0, 4) == ENCBOUND_ERR_STATE);
    assert(encbound_platform_get_config(&config) == 0);
    arena = config.protected_heap_base;
    assert(encbound_heap_init(arena, 0) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_init(arena, 8) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_init(arena, 17) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_init(arena, HEAP_SIZE * 2) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_init(arena + 1, HEAP_SIZE) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_init(UINTPTR_MAX - 15, 16) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_init(0, 16) == ENCBOUND_ERR_ALLOC);
    assert(encbound_runtime_init_with_key(1, 2) == ENCBOUND_OK);
    assert(attempts == 0 && live_bytes == 0);
    assert(encbound_heap_alloc(0, &slot, &radix) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_alloc(16, NULL, &radix) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_alloc(16, &slot, NULL) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_alloc(SIZE_MAX, &slot, &radix) == ENCBOUND_ERR_DEPLETED);
    empty_again();
}

static void sparse_and_ownership(void)
{
    uintptr_t a, b;
    uint32_t ra, rb;
    size_t requested = 999, before;
    assert(encbound_heap_alloc(1, &a, &ra) == ENCBOUND_OK);
    assert(ra == 4 && a == arena);
    /* One small object requires at most one metadata pair per tree level. */
    assert(attempts <= 20 && live_pairs <= 20 && live_bytes < 4096);
    printf("first 1-byte object: %zu metadata requests, %zu payload bytes\n",
           attempts, live_bytes);
    before = live_bytes;
    fail_on(1);
    assert(encbound_heap_alloc(16, &b, &rb) == ENCBOUND_OK);
    assert(attempts == 0 && live_bytes == before && b == a + 16 && rb == 4);
    assert(encbound_heap_init(arena, HEAP_SIZE) == ENCBOUND_ERR_STATE);
    assert(encbound_runtime_init() == ENCBOUND_OK); /* preserves the tree */
    assert(encbound_heap_requested(a, ra, &requested) == ENCBOUND_OK);
    assert(requested == 1);
    assert(encbound_heap_requested(a, ra, NULL) == ENCBOUND_ERR_ALLOC);
    assert(encbound_heap_free(a + 1, ra) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_free(a, ra + 1) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_free(a, ra - 1) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_free(arena + HEAP_SIZE, ra) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_free(arena - 16, ra) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_free(a, 32) == ENCBOUND_ERR_OWNERSHIP);
    requested = 999;
    assert(encbound_heap_requested(a + 1, ra, &requested) == ENCBOUND_ERR_OWNERSHIP);
    assert(requested == 999);
    assert(encbound_heap_free(a, ra) == ENCBOUND_OK);
    assert(encbound_heap_free(a, ra) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_requested(a, ra, &requested) == ENCBOUND_ERR_OWNERSHIP);
    assert(encbound_heap_free(b, rb) == ENCBOUND_OK);
    assert(attempts == 0); /* neither lookup nor free allocates metadata */
    empty_again();
}

static void rollback(void)
{
    size_t f, requested;
    uintptr_t slot, keep;
    uint32_t radix, keep_radix;
    /* Fail each possible split, including the final leaf's parent. */
    for (f = 1; f <= 20; f++) {
        slot = 123; radix = 123;
        fail_on(f);
        assert(encbound_heap_alloc(16, &slot, &radix) == ENCBOUND_ERR_DEPLETED);
        assert(attempts == f && slot == 123 && radix == 123);
        empty_again();
    }
    assert(encbound_heap_alloc(HEAP_SIZE / 2, &keep, &keep_radix) == ENCBOUND_OK);
    memset((void *)keep, 0x5a, 32);
    size_t saved_bytes = live_bytes;
    for (f = 1; f <= 19; f++) {
        fail_on(f);
        assert(encbound_heap_alloc(16, &slot, &radix) == ENCBOUND_ERR_DEPLETED);
        assert(attempts == f && live_bytes == saved_bytes);
        assert(encbound_heap_requested(keep, keep_radix, &requested) == ENCBOUND_OK);
        assert(requested == HEAP_SIZE / 2);
        for (size_t i = 0; i < 32; i++) assert(((unsigned char *)keep)[i] == 0x5a);
        /* Existing free sibling is still usable even while malloc fails. */
        fail_on(1);
        assert(encbound_heap_alloc(HEAP_SIZE / 2, &slot, &radix) == ENCBOUND_OK);
        assert(encbound_heap_free(slot, radix) == ENCBOUND_OK);
        assert(attempts == 0 && live_bytes == saved_bytes);
    }
    assert(encbound_heap_free(keep, keep_radix) == ENCBOUND_OK);
    empty_again();
}

static void realloc_failure(void)
{
    void *a = encbound_malloc(4097), *b;
    uintptr_t raw;
    size_t requested, splits, saved_bytes = live_bytes;
    assert(a);
    assert(encbound_check((uintptr_t)a, 33, ENCBOUND_ACCESS_WRITE, &raw) == ENCBOUND_OK);
    memset((void *)raw, 0xa5, 33);
    fail_on(0);
    b = encbound_malloc(33);
    assert(b);
    splits = attempts;
    assert(splits > 0 && splits <= 20);
    encbound_free(b);
    assert(live_bytes == saved_bytes);
    for (size_t f = 1; f <= splits; f++) {
        fail_on(f);
        assert(encbound_realloc(a, 33) == NULL);
        assert(attempts == f && live_bytes == saved_bytes);
        assert(encbound_heap_requested(raw, 13, &requested) == ENCBOUND_OK && requested == 4097);
        for (size_t i = 0; i < 33; i++) assert(((unsigned char *)raw)[i] == 0xa5);
    }
    fail_on(0);
    b = encbound_realloc(a, 33);
    assert(b);
    assert(encbound_check((uintptr_t)b, 33, ENCBOUND_ACCESS_READ, &raw) == ENCBOUND_OK);
    for (size_t i = 0; i < 33; i++) assert(((unsigned char *)raw)[i] == 0xa5);
    encbound_free(b);
    empty_again();
    fail_on(20);
    assert(encbound_calloc(1, 16) == NULL);
    empty_again();
}

static void many_live(void)
{
    uintptr_t raw;
    peak_bytes = 0;
    for (size_t i = 0; i < MANY; i++) {
        caps[i] = encbound_malloc(16);
        assert(caps[i]);
        assert(encbound_check((uintptr_t)caps[i], 16, ENCBOUND_ACCESS_WRITE, &raw) == ENCBOUND_OK);
        assert(raw == arena + i * 16);
        *(uint32_t *)raw = (uint32_t)i;
    }
    printf("%u live 16-byte objects: %zu metadata payload bytes\n", MANY, live_bytes);
    for (size_t i = 0; i < MANY; i += 2) encbound_free(caps[i]);
    for (size_t i = 1; i < MANY; i += 2) {
        assert(encbound_check((uintptr_t)caps[i], 16, ENCBOUND_ACCESS_READ, &raw) == ENCBOUND_OK);
        assert(*(uint32_t *)raw == i);
    }
    for (size_t i = 0; i < MANY; i += 2) {
        caps[i] = encbound_malloc(16);
        assert(caps[i]);
    }
    for (size_t i = MANY; i > 0; i--) encbound_free(caps[i - 1]);
    empty_again();
}

/* Independent flat occupancy oracle: mixed sizes, fragmented exhaustion,
 * arbitrary free order and requested-length ownership across 20,000 steps. */
static uint32_t random_state = 0x815af273u;
static uint32_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
static void mixed_workload(void)
{
    struct record { uintptr_t slot; uint32_t radix; size_t requested; } records[256] = {{0}};
    size_t failed = 0;
    for (size_t step = 0; step < 20000; step++) {
        struct record *r = &records[next_random() % 256];
        if (r->requested) {
            size_t requested;
            size_t first = (r->slot - arena) / 16, count = ((size_t)1 << r->radix) / 16;
            assert(encbound_heap_requested(r->slot, r->radix, &requested) == ENCBOUND_OK);
            assert(requested == r->requested);
            assert(encbound_heap_free(r->slot, r->radix) == ENCBOUND_OK);
            for (size_t j = first; j < first + count; j++) {
                assert(occupied[j]); occupied[j] = 0;
            }
            r->requested = 0;
        } else {
            size_t size = ((size_t)1 << (4 + next_random() % 18)) - next_random() % 8;
            size_t rounded = 16;
            while (rounded < size) rounded *= 2;
            int rc = encbound_heap_alloc(size, &r->slot, &r->radix);
            if (rc == ENCBOUND_OK) {
                assert(((size_t)1 << r->radix) == rounded && (r->slot & (rounded - 1)) == 0);
                assert(r->slot >= arena && r->slot - arena <= HEAP_SIZE - rounded);
                size_t first = (r->slot - arena) / 16;
                for (size_t j = first; j < first + rounded / 16; j++) {
                    assert(!occupied[j]); occupied[j] = 1;
                }
                r->requested = size;
            } else {
                assert(rc == ENCBOUND_ERR_DEPLETED); failed++;
                for (size_t first = 0; first < sizeof(occupied); first += rounded / 16) {
                    size_t j;
                    for (j = first; j < first + rounded / 16; j++) if (occupied[j]) break;
                    assert(j < first + rounded / 16); /* no fitting aligned hole */
                }
            }
        }
    }
    assert(failed > 0);
    for (size_t i = 0; i < 256; i++) if (records[i].requested)
        assert(encbound_heap_free(records[i].slot, records[i].radix) == ENCBOUND_OK);
    empty_again();
    printf("mixed workload: 20000 operations, %zu independently verified exhaustion cases\n", failed);
}

int main(void)
{
    initialization();
    sparse_and_ownership();
    rollback();
    realloc_failure();
    many_live();
    mixed_workload();
    puts("ALLOCATOR PASS: ownership, sparsity, rollback, realloc, capacity and fragmentation");
    return 0;
}
