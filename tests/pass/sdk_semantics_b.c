/*
 * ENCBound restart - C4 companion application unit
 * (docs/legacy/steps/04a-capability-semantics.md C4).
 *
 * Compiled as a separate translation unit through tools/encbound-cc.sh and
 * linked only into the SDK diagnostic enclave. It exists to show that a
 * capability passed from one instrumented unit is preserved full-width when the
 * callee stores it, round-trips it through an integer and reads it back, and
 * that an ordinary access in the callee is still checked.
 */
#include <stddef.h>
#include <stdint.h>

int semantics_cross_unit(unsigned char *p)
{
    unsigned char *volatile slot = p;
    volatile uintptr_t bits;
    unsigned char *q;

    p[3] = 0x5a; /* cross-unit checked store */
    if (p[3] != 0x5a) return 0;

    bits = (uintptr_t)slot;
    q = (unsigned char *)bits;
    if (q != p || slot != p) return 0;

    return slot[3] == 0x5a && q[3] == 0x5a;
}

/* Separate compilation keeps both choices observable to the caller. At -O0
   this has a pointer PHI; at -O2 it has a pointer select. Both inputs are live. */
__attribute__((noinline))
unsigned char *semantics_choose(unsigned char *a, unsigned char *b, int first)
{
    return first ? a : b;
}
