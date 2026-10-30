/*
 * ENCBound restart - E1 instrumented authentication-contrast fixture
 * (docs/legacy/steps/10-evaluation-campaign.md E1).
 *
 * This is a test-only application-domain unit. It is compiled through
 * tools/encbound-cc.sh (the protected driver) so its ordinary memory
 * operations carry compiler-inserted checks, and it is linked only into the
 * SDK diagnostic enclave, never into the wallet.
 *
 * The experiment allocates two distinct live 16-byte heap slots A and B
 * (radix 4). It then corrupts capability bits explicitly: the forged value
 * keeps slot A's radix/tag in bits 63..32 and takes slot B's offset from bits
 * 31..0, addressing an interior byte of B. No minting service is exposed and
 * the corruption is plain integer mask/or arithmetic on the returned
 * capability values, not undefined C pointer arithmetic.
 *
 * Observed values are reported through the trusted observer `forgery_report`,
 * because an instrumented unit must not write through a raw untagged pointer.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "encbound_common.h"

/* Implemented in sdk/forgery_probe.c (trusted). */
extern int forgery_report(uint32_t index, uint64_t value);
/* Instrumented LZ4 round-trip fixture (tests/pass/sdk_lz4.c). */
extern int lz4_probe(void);

enum {
    FORGERY_CASE_VALID = 0,
    FORGERY_CASE_FIT = 1,
    FORGERY_CASE_RANGE = 2,
    FORGERY_CASE_RAW = 3,
    FORGERY_CASE_STACK_FIT = 4,
    FORGERY_CASE_LZ4 = 5,
    FORGERY_CASE_TRUSTED = 6
};

#define FORGERY_SLOT 16u

__attribute__((noinline)) static int case_valid(void)
{
    volatile unsigned char *a = malloc(FORGERY_SLOT);
    volatile unsigned char *b = malloc(FORGERY_SLOT);
    int ok;

    if (a == NULL || b == NULL) {
        return 10;
    }
    a[0] = 0x11;
    b[0] = 0x22;
    forgery_report(0, a[0]);
    forgery_report(1, b[0]);
    ok = (a[0] == 0x11) && (b[0] == 0x22);
    free((void *)a);
    free((void *)b);
    return ok ? 0 : 11;
}

__attribute__((noinline)) static int case_fit(void)
{
    unsigned char *a = malloc(FORGERY_SLOT);
    unsigned char *b = malloc(FORGERY_SLOT);
    uintptr_t ac;
    uintptr_t bc;
    uintptr_t forged;
    volatile unsigned char *p;
    unsigned char after;

    if (a == NULL || b == NULL) {
        return 10;
    }
    b[2] = 0x33; /* valid store: the known target byte */
    ac = (uintptr_t)a;
    bc = (uintptr_t)b;
    forged = (ac & ~(uintptr_t)ENCBOUND_OFFSET_MASK) |
             (((bc & ENCBOUND_OFFSET_MASK) + 2u) & ENCBOUND_OFFSET_MASK);
    forgery_report(0, forged);
    forgery_report(1, 0x33);
    p = (volatile unsigned char *)forged;
    *p = 0x5a; /* forged store: TAG rejection in MAC27 if the tags differ */
    after = b[2];
    forgery_report(2, after);
    free(a);
    free(b);
    return after == 0x5a ? 0 : 12;
}

__attribute__((noinline)) static int case_range(void)
{
    unsigned char *a = malloc(FORGERY_SLOT);
    unsigned char *b = malloc(FORGERY_SLOT);
    uintptr_t ac;
    uintptr_t bc;
    uintptr_t forged;
    volatile uint16_t *p;

    if (a == NULL || b == NULL) {
        return 10;
    }
    ac = (uintptr_t)a;
    bc = (uintptr_t)b;
    forged = (ac & ~(uintptr_t)ENCBOUND_OFFSET_MASK) |
             (((bc & ENCBOUND_OFFSET_MASK) + (FORGERY_SLOT - 1u)) &
              ENCBOUND_OFFSET_MASK);
    forgery_report(0, forged);
    p = (volatile uint16_t *)forged;
    *p = 0x5a5a; /* width 2 crosses the 16-byte slot end: RANGE in both */
    free(a);
    free(b);
    return 0;
}

__attribute__((noinline)) static int case_raw(uintptr_t raw)
{
    volatile unsigned char *p = (volatile unsigned char *)raw;

    forgery_report(0, raw);
    *p = 0x5a; /* untagged address inside the protected arena: POLICY denial */
    return 0;
}

__attribute__((noinline)) static int case_stack_fit(void)
{
    volatile unsigned char a[FORGERY_SLOT];
    volatile unsigned char b[FORGERY_SLOT];
    uintptr_t ac;
    uintptr_t bc;
    uintptr_t forged;
    volatile unsigned char *p;
    unsigned char after;

    a[0] = 0x44;
    b[2] = 0x33; /* valid store into a minted stack slot */
    ac = (uintptr_t)a;
    bc = (uintptr_t)b;
    forged = (ac & ~(uintptr_t)ENCBOUND_OFFSET_MASK) |
             (((bc & ENCBOUND_OFFSET_MASK) + 2u) & ENCBOUND_OFFSET_MASK);
    forgery_report(0, forged);
    forgery_report(1, 0x33);
    p = (volatile unsigned char *)forged;
    *p = 0x5a; /* forged stack access: TAG in MAC27, executes in RADIX_ONLY */
    after = b[2];
    forgery_report(2, after);
    return (after == 0x5a) ? 0 : 12;
}

int forgery_dispatch(uint32_t case_id, uintptr_t raw)
{
    switch (case_id) {
    case FORGERY_CASE_VALID:
        return case_valid();
    case FORGERY_CASE_FIT:
        return case_fit();
    case FORGERY_CASE_RANGE:
        return case_range();
    case FORGERY_CASE_RAW:
        return case_raw(raw);
    case FORGERY_CASE_TRUSTED:
        return case_raw(raw); /* trusted-image pointer: POLICY, not app-owned */
    case FORGERY_CASE_STACK_FIT:
        return case_stack_fit();
    case FORGERY_CASE_LZ4:
        return lz4_probe();
    default:
        return 3;
    }
}
