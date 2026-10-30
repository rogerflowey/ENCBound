/* Instrumented test work, called by a trusted startup observer BEFORE bridges.
 * This deliberately has no llvm.global_ctors: lifecycle admission is separate. */
#include <stdint.h>
#include <stdlib.h>

static volatile unsigned seed = 37, other = 90;
static volatile unsigned *fixed = &seed;
static unsigned char *held;
static unsigned visits, started;

__attribute__((noinline))
static unsigned stack_sum(volatile unsigned *p)
{
    return p[0]+p[1]+p[2]+p[3];
}

int startup_work(void)
{
    volatile unsigned local[4] = {3, 5, 7, 11};
    if (stack_sum(local) != 26 || *fixed != 37) return -1;
    held = malloc(32);
    if (!held) return -2;
    held[0] = 0x5a;
#ifdef STARTUP_FAULT
    /* An executed checked two-byte store straddles the rounded heap slot. */
    *(volatile uint16_t *)(held+31) = 0x1234;
#endif
    *fixed += 5;
    fixed = &other; /* Later initialize() must not reapply the original fixup. */
    started = 1;
    return seed;
}

uintptr_t startup_heap_bits(void) { return (uintptr_t)held; }
uintptr_t startup_global_bits(void) { return (uintptr_t)&seed; }

int step(int action)
{
    if (started != 1 || seed != 42 || fixed != &other ||
        *fixed != 90+visits || !held || held[0] != 0x5a+visits) return -10;
    if (action == 1) {
        free(held);
        held = 0;
        started = 2;
        return 0;
    }
    unsigned char *temporary = malloc(32);
    if (!temporary || temporary == held) return -11;
    temporary[0] = 0x21;
    if (held[0] != 0x5a+visits) return -12;
    free(temporary);
    ++*fixed;
    ++held[0];
    return 100+(int)++visits;
}
