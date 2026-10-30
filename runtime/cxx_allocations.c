/* Application-only C++ allocation adapters. No global operator interposition.
 * Ordinary new has terminal exhaustion semantics in the no-exception profile;
 * nothrow new returns NULL. new_handler is deliberately unsupported.
 * Build separately with ENCBOUND_CXX_BASELINE for matched native allocation.
 */
#include <stddef.h>
#include <stdlib.h>
#ifndef ENCBOUND_CXX_BASELINE
#include "encbound_runtime.h"
#include "encbound_platform.h"
#endif

static void *allocate(size_t size, size_t alignment, int terminal)
{
    void *p = NULL;
    if (size == 0) size = 1;
    if (alignment && !(alignment & (alignment - 1))) {
#ifdef ENCBOUND_CXX_BASELINE
        if (alignment <= 16) p = malloc(size);
        else if (size <= (size_t)-1 - (alignment - 1))
            p = aligned_alloc(alignment, (size + alignment - 1) & ~(alignment - 1));
#else
        p = encbound_alloc_aligned(size, alignment);
#endif
    }
    if (!p && terminal) {
#ifdef ENCBOUND_CXX_BASELINE
        abort();
#else
        encbound_abort(ENCBOUND_ERR_DEPLETED);
#endif
    }
    return p;
}
void *encbound_cxx_new(size_t n) { return allocate(n, 16, 1); }
void *encbound_cxx_new_nothrow(size_t n, const void *tag)
{ (void)tag; return allocate(n, 16, 0); }
void *encbound_cxx_new_aligned(size_t n, size_t a) { return allocate(n, a, 1); }
void *encbound_cxx_new_aligned_nothrow(size_t n, size_t a, const void *tag)
{ (void)tag; return allocate(n, a, 0); }
void encbound_cxx_delete(void *p)
{
#ifdef ENCBOUND_CXX_BASELINE
    free(p);
#else
    encbound_free(p);
#endif
}
void encbound_cxx_delete_sized(void *p, size_t n)
{ (void)n; encbound_cxx_delete(p); }
void encbound_cxx_delete_nothrow(void *p, const void *tag)
{ (void)tag; encbound_cxx_delete(p); }
void encbound_cxx_delete_aligned(void *p, size_t a)
{ (void)a; encbound_cxx_delete(p); }
void encbound_cxx_delete_sized_aligned(void *p, size_t n, size_t a)
{ (void)n; (void)a; encbound_cxx_delete(p); }
void encbound_cxx_delete_aligned_nothrow(void *p, size_t a, const void *tag)
{ (void)a; (void)tag; encbound_cxx_delete(p); }
