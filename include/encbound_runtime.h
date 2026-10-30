/*
 * ENCBound restart - narrow runtime API.
 *
 * The compiler pass calls these. Application-visible pointers are capabilities
 * (pointer-sized tagged values); raw addresses never leave this module except
 * through encbound_check's output for the immediately following access.
 */

#ifndef ENCBOUND_RUNTIME_H
#define ENCBOUND_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#include "encbound_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int encbound_runtime_ready(void);

/* Compiler-private fixed-entry read of the trusted global capability table. */
uintptr_t encbound_global_cap(const uintptr_t *entry);

/* Initialize with a caller-supplied key (isolated tests only). */
int encbound_runtime_init_with_key(uint64_t k0, uint64_t k1);
/* Initialize using the platform random source (deployment path). */
int encbound_runtime_init(void);

/*
 * Validate a capability for an access of `width` bytes of the given kind.
 * On success writes the raw address to *raw and returns ENCBOUND_OK.
 * On failure returns an error category and calls encbound_abort(); *raw is
 * not written.
 */
int encbound_check(uintptr_t capability, size_t width, int kind,
                   uintptr_t *raw);

/*
 * Check and, on failure, invoke the terminal abort path. Returns the raw
 * address on success. This is the entry the compiler pass emits.
 */
uintptr_t encbound_require(uintptr_t capability, size_t width, int kind);

/* Compiler-private guarded span reuse. The pass rejects source-level calls and
 * confines preparation tokens to matching guarded accesses; not an app API. */
uintptr_t encbound_span_prepare(uintptr_t anchor);
uintptr_t encbound_span_require(uintptr_t capability, size_t width, int kind,
                               uintptr_t anchor, uintptr_t token);


/*
 * Validate a capability and report the raw start address plus the number of
 * bytes from that address to the end of its containing slot (tagged) or COMPAT
 * region (untagged). Used by the bounded library adapters; abort-free.
 */
int encbound_check_extent(uintptr_t capability, uintptr_t *raw,
                          size_t *remaining_out);

/* Application allocation API. Returned pointers are capabilities. */
void *encbound_malloc(size_t size);
/* Internal adapter entry; size is recorded separately from aligned capacity. */
void *encbound_alloc_aligned(size_t size, size_t alignment);
void *encbound_calloc(size_t count, size_t size);
void *encbound_realloc(void *capability, size_t size);
void encbound_free(void *capability);

/*
 * Checked library adapters. Trusted code: they validate complete capability
 * ranges through the runtime before touching raw memory, and never return or
 * expose a raw address. The pass redirects application call sites here; SDK
 * internal calls still use the raw routines.
 */
void *encbound_memcpy(void *dst, const void *src, size_t n);
void *encbound_memmove(void *dst, const void *src, size_t n);
void *encbound_memset(void *dst, int c, size_t n);
int encbound_memcmp(const void *a, const void *b, size_t n);
size_t encbound_strlen(const char *s);
size_t encbound_strnlen(const char *s, size_t maxlen);
int encbound_strcmp(const char *a, const char *b);
char *encbound_strncpy(char *dst, const char *src, size_t n);
char *encbound_strncat(char *dst, const char *src, size_t n);
/* Only the literal "%s" / one-string snprintf subset is admitted. */
int encbound_snprintf_string(char *dst, size_t n, const char *format,
                            const char *src);

/*
 * Compiler-only stack slot mint. Validates that [slot, slot+slot_size) is a
 * power-of-two-aligned slot inside the platform stack region, clears the whole
 * slot, and returns a stack-domain capability. Never callable from application
 * source (build audit).
 */
int encbound_stack_slot(void *slot_address, size_t slot_size,
                        void **capability_out);

/*
 * Compiler-generated form: validate the slot, clear it, and return the stack
 * capability by value, aborting on bad geometry. Only the pass may emit calls;
 * application source calls are rejected by the step 4 build audit.
 */
uintptr_t encbound_stack_mint(void *slot_address, size_t slot_size);

/* Compiler-only dynamic-stack protocol. prepare runs BEFORE moving SP;
 * mint_dynamic receives the fresh 2*slot reservation, never an app address. */
size_t encbound_stack_prepare(void *stack_pointer, size_t count,
                              size_t element_size, size_t alignment);
size_t encbound_stack_product(size_t a, size_t b);
uintptr_t encbound_stack_mint_dynamic(void *reservation, size_t slot_size);

#ifdef __cplusplus
}
#endif

#endif /* ENCBOUND_RUNTIME_H */
