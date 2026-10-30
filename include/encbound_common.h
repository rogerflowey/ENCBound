/*
 * ENCBound restart - shared pointer/runtime constants.
 *
 * This is the single source of truth for the pointer layout and error
 * categories. The runtime and (later) the LLVM pass include it; do not
 * duplicate these constants elsewhere.
 */

#ifndef ENCBOUND_COMMON_H
#define ENCBOUND_COMMON_H

#include <stdint.h>

/* Pointer layout: [radix:5][tag:27][enclave offset:32] */
#define ENCBOUND_RADIX_MIN 1u
#define ENCBOUND_RADIX_MAX 30u
#define ENCBOUND_OFFSET_BITS 32u
#define ENCBOUND_OFFSET_MASK 0xffffffffull
#define ENCBOUND_TAG_BITS 27u
#define ENCBOUND_TAG_MASK 0x07ffffffull
#define ENCBOUND_RADIX_SHIFT 59u
#define ENCBOUND_TAG_SHIFT 32u

/* Access kinds passed to the check. */
#define ENCBOUND_ACCESS_READ 1
#define ENCBOUND_ACCESS_WRITE 2
#define ENCBOUND_ACCESS_READWRITE 3

/* Error categories (stable; used by tests and diagnostics). */
#define ENCBOUND_OK 0
#define ENCBOUND_ERR_STATE 1       /* runtime/platform not initialized */
#define ENCBOUND_ERR_ENCODING 2    /* malformed pointer encoding */
#define ENCBOUND_ERR_POLICY 3      /* policy forbids the untagged access */
#define ENCBOUND_ERR_RANGE 4       /* access crosses slot or region */
#define ENCBOUND_ERR_TAG 5         /* MAC27 authentication failed */
#define ENCBOUND_ERR_ALLOC 6       /* allocation request invalid */
#define ENCBOUND_ERR_DEPLETED 7    /* arena or record table exhausted */
#define ENCBOUND_ERR_OWNERSHIP 8   /* free/realloc of a non-owned object */
#define ENCBOUND_ERR_DOMAIN 9      /* wrong domain for the operation */

#endif /* ENCBOUND_COMMON_H */
