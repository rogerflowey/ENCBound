/*
 * ENCBound restart - sparse buddy tree over the fixed protected arena.
 *
 * The root is static trusted state. Each split allocates a pair of children
 * using trusted SDK malloc (host malloc in native tests). Application storage
 * never comes from that heap. Coalescing releases the pair. No tree lookup is
 * part of a dereference check; this is allocation/ownership bookkeeping only.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "encbound_common.h"
#include "encbound_internal.h"

#define ENCBOUND_HEAP_MIN_ORDER 4u /* 16-byte minimum slot */
#define ENCBOUND_HEAP_MAX_SUPPORTED_ORDER 24u
#define ENCBOUND_HEAP_MAX_DEPTH \
    (ENCBOUND_HEAP_MAX_SUPPORTED_ORDER - ENCBOUND_HEAP_MIN_ORDER)

typedef struct heap_node {
    struct heap_node *children; /* NULL for a leaf; otherwise a pair */
    size_t requested;           /* nonzero only for an allocated leaf */
    uint32_t largest;           /* largest free order below here, or 0 */
} heap_node_t;

static heap_node_t g_root;
static uintptr_t g_arena;
static uint64_t g_arena_size;
static uint32_t g_max_order;
static int g_heap_ready;

static void init_free(heap_node_t *node, uint32_t order)
{
    node->children = NULL;
    node->requested = 0;
    node->largest = order;
}

static void update_largest(heap_node_t *node)
{
    uint32_t left = node->children[0].largest;
    uint32_t right = node->children[1].largest;
    node->largest = left > right ? left : right;
}

int encbound_heap_init(uintptr_t base, uint64_t size)
{
    /* A repeated bootstrap must not discard live records or leak children. */
    if (g_heap_ready) {
        return ENCBOUND_ERR_STATE;
    }
    if (size < (1ull << ENCBOUND_HEAP_MIN_ORDER) ||
        size > (1ull << ENCBOUND_HEAP_MAX_SUPPORTED_ORDER) ||
        (size & (size - 1)) != 0 || (base & (size - 1)) != 0 ||
        base == 0 || base > UINTPTR_MAX - size) {
        return ENCBOUND_ERR_ALLOC;
    }
    g_arena = base;
    g_arena_size = size;
    g_max_order = ENCBOUND_HEAP_MIN_ORDER;
    while ((1ull << g_max_order) < size) {
        g_max_order++;
    }
    init_free(&g_root, g_max_order);
    g_heap_ready = 1;
    return ENCBOUND_OK;
}

/* Descend one suitable branch, preferring the lower address. A failed metadata
 * allocation unwinds all splits created by this request; old nodes, summaries
 * and allocations remain unchanged. Recursion is bounded by MAX_DEPTH. */
static int allocate_node(heap_node_t *node, uint32_t order, uint32_t target,
                         size_t requested, uintptr_t *offset_out)
{
    int split = 0;
    int rc;
    unsigned child;
    uintptr_t offset;

    if (order == target) {
        /* largest >= target at entry implies this is a free leaf. */
        node->requested = requested;
        node->largest = 0;
        *offset_out = 0;
        return ENCBOUND_OK;
    }
    if (node->children == NULL) {
        node->children = malloc(2 * sizeof(*node->children));
        if (node->children == NULL) {
            return ENCBOUND_ERR_DEPLETED;
        }
        init_free(&node->children[0], order - 1);
        init_free(&node->children[1], order - 1);
        split = 1;
    }
    child = node->children[0].largest >= target ? 0u : 1u;
    rc = allocate_node(&node->children[child], order - 1, target,
                       requested, &offset);
    if (rc != ENCBOUND_OK) {
        if (split) {
            free(node->children);
            node->children = NULL;
        }
        return rc;
    }
    update_largest(node);
    *offset_out = offset + ((uintptr_t)child << (order - 1));
    return ENCBOUND_OK;
}

int encbound_heap_alloc_aligned(size_t size, size_t alignment,
                                uintptr_t *slot_out, uint32_t *radix_out)
{
    uint32_t target = ENCBOUND_HEAP_MIN_ORDER;
    uintptr_t offset;
    int rc;

    if (!g_heap_ready || slot_out == NULL || radix_out == NULL || size == 0 ||
        alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return ENCBOUND_ERR_ALLOC;
    }
    if (size > g_arena_size || alignment > g_arena_size) {
        return ENCBOUND_ERR_DEPLETED;
    }
    while (((size_t)1 << target) < size || ((size_t)1 << target) < alignment) {
        target++;
    }
    if (g_root.largest < target) {
        return ENCBOUND_ERR_DEPLETED;
    }
    rc = allocate_node(&g_root, g_max_order, target, size, &offset);
    if (rc != ENCBOUND_OK) {
        return rc;
    }
    *slot_out = g_arena + offset;
    *radix_out = target;
    return ENCBOUND_OK;
}

int encbound_heap_alloc(size_t size, uintptr_t *slot_out, uint32_t *radix_out)
{
    return encbound_heap_alloc_aligned(size, 1, slot_out, radix_out);
}

/* Walk address bits to an exact allocated leaf. Optional path contains only
 * its parents, from root downward, for the free/coalescing walk. */
static heap_node_t *find_live(uintptr_t slot, uint32_t radix,
                              heap_node_t **path, size_t *depth)
{
    heap_node_t *node = &g_root;
    uint32_t order = g_max_order;
    uintptr_t offset;

    if (radix < ENCBOUND_HEAP_MIN_ORDER || radix > g_max_order ||
        slot < g_arena || slot - g_arena >= g_arena_size) {
        return NULL;
    }
    offset = slot - g_arena;
    if ((offset & (((uintptr_t)1 << radix) - 1)) != 0) {
        return NULL;
    }
    while (order > radix) {
        if (node->children == NULL) {
            return NULL;
        }
        if (path != NULL) {
            path[(*depth)++] = node;
        }
        order--;
        node = &node->children[(offset >> order) & 1u];
    }
    return node->children == NULL && node->requested != 0 ? node : NULL;
}

int encbound_heap_requested(uintptr_t slot, uint32_t radix, size_t *size_out)
{
    heap_node_t *node;
    if (!g_heap_ready || size_out == NULL) {
        return ENCBOUND_ERR_ALLOC;
    }
    node = find_live(slot, radix, NULL, NULL);
    if (node == NULL) {
        return ENCBOUND_ERR_OWNERSHIP;
    }
    *size_out = node->requested;
    return ENCBOUND_OK;
}

int encbound_heap_free(uintptr_t slot, uint32_t radix)
{
    heap_node_t *path[ENCBOUND_HEAP_MAX_DEPTH];
    heap_node_t *node;
    size_t depth = 0;
    uint32_t order = radix;

    if (!g_heap_ready) {
        return ENCBOUND_ERR_STATE;
    }
    node = find_live(slot, radix, path, &depth);
    if (node == NULL) {
        return ENCBOUND_ERR_OWNERSHIP;
    }
    init_free(node, order);
    while (depth != 0) {
        heap_node_t *parent = path[--depth];
        /* Only whole free leaves have largest == their own order. */
        if (parent->children[0].largest == order &&
            parent->children[1].largest == order) {
            free(parent->children);
            init_free(parent, order + 1);
        } else {
            update_largest(parent);
        }
        order++;
    }
    return ENCBOUND_OK;
}
