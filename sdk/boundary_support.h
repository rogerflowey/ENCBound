/*
 * ENCBound restart - shared trusted boundary support (docs/legacy/steps/09-original-api-and-sessions.md).
 *
 * Reusable instance admission and per-call buffer lifecycle operations used by
 * the generated direct ECALL adapters. This is small handwritten trusted code,
 * counted separately from generated C: it contains no application-specific
 * operation or payload semantics.
 *
 * The generated adapter owns one call's request sequence; these helpers own the
 * shared serial admission gate, initialize-once runtime entry and the
 * protected-or-ordinary buffer lifecycle, so that every public ECALL reuses the
 * same mechanics. Per-call cleanup releases only the adapter's own marshaling
 * allocations; application heap allocations survive across calls.
 */

#ifndef ENCBOUND_BOUNDARY_SUPPORT_H
#define ENCBOUND_BOUNDARY_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Boundary/transport results returned by generated ECALL adapters in place of
 * the application status. Negative to stay distinct from an application's own
 * non-negative RET_* codes; application codes are returned unchanged.
 */
#define ENCBOUND_REQ_ERR_ARG (-1)
#define ENCBOUND_REQ_ERR_TOO_LARGE (-2)
#define ENCBOUND_REQ_ERR_PLATFORM (-3)
#define ENCBOUND_REQ_ERR_ALLOC (-4)
#define ENCBOUND_REQ_ERR_STATE (-5)

/*
 * Shared serial admission gate. Exactly one application invocation runs at a
 * time across all public ECALLs. The gate is held across OCALLs.
 *
 *   admit()   returns 0 and marks the gate active if it was idle, otherwise
 *             returns non-zero (a nested/overlapping entry or a terminal
 *             session). A caller that did not acquire the gate must not run an
 *             outer call's cleanup.
 *   release() returns an active call to idle after ordinary results and
 *             recoverable boundary errors.
 *   fail()    marks the session terminal after a protection abort, a broken
 *             runtime invariant or a failed initialization. Later calls can
 *             never re-initialize or enter the application.
 */
int encbound_boundary_admit(void);
void encbound_boundary_release(void);
void encbound_boundary_fail(void);

/*
 * Initialize the protected platform/runtime exactly once per enclave, under the
 * held admission gate or the SDK's exclusive first-entry startup path. The
 * optional early_bootstrap.c entry uses the latter without holding the call
 * gate across constructors. Returns 0 on success. In ordinary (BASELINE) profiles it
 * is a no-op. A failure is sticky: later calls fail rather than initialize
 * again, so a partially initialized session can never enter the application.
 */
int encbound_boundary_initialize(void);

/*
 * Buffer lifecycle owned by generated code. Protected profiles return checked
 * capabilities through the runtime; ordinary profiles use malloc/free. The
 * width arguments are the exact extent the caller will touch and are validated
 * in protected profiles (and are inherently satisfied by an unrounded buffer in
 * ordinary profiles).
 */
void *encbound_boundary_alloc(size_t size);
void encbound_boundary_free(void *capability);
uint8_t *encbound_boundary_write(void *capability, size_t width);
const uint8_t *encbound_boundary_read(const void *capability, size_t width);

/*
 * Bounded scan for the NUL that the pinned Intel bridge guarantees at the end
 * of an enclave-local [in, string] copy. Returns the string length (excluding
 * NUL) or (size_t)-1 when no NUL occurs within `cap` bytes. This scans only the
 * bridge-owned buffer; it never touches host memory.
 */
size_t encbound_boundary_strnlen(const char *pointer, size_t cap);

#endif /* ENCBOUND_BOUNDARY_SUPPORT_H */
