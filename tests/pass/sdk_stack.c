/*
 * ENCBound restart - C4 executed behavior matrix, instrumented SDK SIM fixture
 * (docs/legacy/steps/04a-capability-semantics.md C4; docs/legacy/steps/10-evaluation-campaign.md E0).
 *
 * This is a test-only application-domain unit. It is compiled through
 * tools/encbound-cc.sh so its ordinary memory operations carry compiler-inserted
 * checks, and it is linked only into the SDK diagnostic enclave, never into the
 * wallet. It executes the positive half of the C4 table in Intel SGX SDK
 * simulation in both protected profiles and at both frontend levels:
 *
 *   - heap and addressable stack arrays/structures, contents after writes and
 *     nested calls;
 *   - interior and negative offsets; one-past formation without access;
 *   - equality, same-object ordering and differences, with no unrelated-object
 *     ordering promise;
 *   - pointer/integer and pointer-in-memory round trips; PHI and select;
 *   - fixed-width scalar and volatile accesses; memcpy/move/set, overlap and
 *     a zero-length no-op;
 *   - newly exposed stack slots: alignment and whole-slot clearing.
 *
 * The negative authentication cases (corrupted tag, stripped/raw and
 * trusted-region pointers, edge-straddling range) live in the E1 forgery
 * contrast (tests/pass/sdk_forgery.c, tools/run_forgery_contrast.sh). Values are
 * observed only through trusted test helpers, never written through a raw
 * untagged pointer.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Trusted observer: authenticates a newly minted slot, its alignment, extent
   and whole-slot clearing. Implemented in sdk/runtime_probe.c. */
extern int probe_new_stack_slot(const void *cap, size_t rounded);

/* Companion instrumented application unit (tests/pass/sdk_semantics_b.c):
   pointer/integer round-trip preservation across a separately compiled unit. */
extern int semantics_cross_unit(unsigned char *p);
extern unsigned char *semantics_choose(unsigned char *a, unsigned char *b,
                                       int first);

struct pair {
    unsigned int a;
    unsigned short b;
    unsigned char c;
};

__attribute__((noinline)) static int struct_roundtrip(struct pair *s)
{
    s->a = 0x11223344u;
    s->b = 0x5566u;
    s->c = 0x77u;
    return s->a == 0x11223344u && s->b == 0x5566u && s->c == 0x77u;
}

__attribute__((noinline)) static int nested(unsigned char *heap)
{
    volatile unsigned char local[33];
    if (!probe_new_stack_slot((const void *)local, 64)) return 0;
    local[0] = heap[0];
    local[32] = heap[7];
    return local[0] == 19 && local[32] == 23;
}

/* Keep these ordinary local accesses in IR so the opt-in local proof rule is
 * executed on the real SDK stack. optnone is confined to this test fixture;
 * the production application frontend/code generator are not changed. */
__attribute__((noinline,optnone)) static int local_proof_roundtrip(void)
{
    unsigned char bytes[16];
    bytes[0] = 37;
    bytes[15] = 91;
    return bytes[0] + bytes[15] == 128;
}

int application_stack_probe(void)
{
    volatile unsigned char local[17];
    unsigned char *heap;
    unsigned char *heap2;
    volatile uintptr_t stored;
    unsigned char *volatile pointer_slot;
    unsigned char *volatile interior_slot;
    unsigned char *volatile end_slot;
    volatile size_t offset = 7;
    volatile ptrdiff_t backwards = -1;
    volatile size_t full_length = 16;
    volatile size_t overlap_length = 15;
    volatile size_t zero_length = 0;
    volatile int choose_first = 1;
    volatile int choose_second = 0;
    unsigned char *interior;
    unsigned char *end;
    struct pair sp;
    volatile uint16_t scalar;
    typedef uint32_t lanes4 __attribute__((vector_size(16)));
    volatile lanes4 vector = { 1, 2, 3, 4 };
    int ok;

    if (!local_proof_roundtrip()) return 0;

    /* Newly exposed stack slot: alignment, extent, whole-slot clearing. */
    if (!probe_new_stack_slot((const void *)local, 32)) return 0;
    local[0] = 71;
    local[16] = 83;

    heap = malloc(16);
    heap2 = malloc(16);
    if (!heap || !heap2) return 0;
    heap[0] = 19;
    heap[7] = 23;
    heap2[0] = 0xa1;

    /* Equality, same-object ordering and differences; distinct live objects. */
    interior_slot = heap + offset;
    interior = interior_slot;
    ok = interior == heap + 7 && interior > heap && interior - heap == 7 &&
         heap != heap2;

    /* Interior read; negative offset write; one-past formation, no access. */
    ok = ok && *interior == 23;
    interior[backwards] = 41; /* heap[6], runtime negative index */
    ok = ok && heap[6] == 41;
    end_slot = heap + full_length;
    end = end_slot;
    ok = ok && end - heap == 16 && end > interior;

    /* Pointer/integer and pointer-in-memory round trips; PHI and select. */
    pointer_slot = heap;
    stored = (uintptr_t)pointer_slot;
    ok = ok && (unsigned char *)stored == heap &&
         ((unsigned char *)stored)[7] == 23;
    {
        unsigned char *slot = pointer_slot;
        ok = ok && slot == heap && slot[0] == 19;
    }
    {
        unsigned char *first = semantics_choose(heap, heap2, choose_first);
        unsigned char *second = semantics_choose(heap, heap2, choose_second);
        ok = ok && first == heap && second == heap2 &&
             first[7] == 23 && second[0] == 0xa1;
    }

    /* Stack structure and nested call. */
    ok = ok && struct_roundtrip(&sp) && sp.c == 0x77u && nested(heap);

    /* Scalar/volatile access and memcpy/move/set with overlap and zero length. */
    scalar = 0x1234u;
    ok = ok && scalar == 0x1234u && vector[0] + vector[3] == 5;
    __builtin_memcpy(heap2, heap, full_length);
    ok = ok && heap2[6] == 41 && heap2[7] == 23;
    __builtin_memmove(heap2 + 1, heap2, overlap_length); /* overlapping move */
    ok = ok && heap2[8] == 23;
    __builtin_memset(heap2, 0, full_length);
    ok = ok && heap2[0] == 0 && heap2[15] == 0;
    __builtin_memcpy(heap2, heap, zero_length); /* runtime zero: no access */
    __builtin_memmove(heap2, heap, zero_length);
    __builtin_memset(heap2, 0xa5, zero_length);
    ok = ok && heap2[0] == 0;

    /* Cross-translation-unit pointer preservation. */
    ok = ok && semantics_cross_unit(heap) == 1;

    ok = ok && local[0] == 71 && local[16] == 83;
    free(heap);
    free(heap2);
    return ok;
}
