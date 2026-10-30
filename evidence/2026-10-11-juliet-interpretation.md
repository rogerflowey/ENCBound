# Interpreting the first Juliet pilot

This interpretation uses the initial 117 cases. The subsequent
[adapter extension](2026-10-11-juliet-adapters.md) adds twelve cases rejected
by both protected profiles and preserves these original outcome categories.

Read-only analysis of the final pilot's `selection.json`, `results.jsonl`,
retained source/IR and debugger traces. No new execution, mechanism change or
gate completion. The [original pilot record](2026-10-11-juliet-pilot.md) remains
the raw result; this interpretation does not alter its outcomes or denominator.

## Paired authentication evidence

For the same 117 bad cases:

| RADIX_ONLY outcome | MAC27 outcome | Cases |
| --- | --- | ---: |
| Attributed rejection | Attributed rejection | 70 |
| Normal return | Attributed rejection | 24 |
| Timeout | Attributed rejection | 1 |
| SIGSEGV | Attributed rejection | 1 |
| Normal return | Normal return | 21 |

All 26 additional MAC27 rejections have TAG code 5: 24 instrumented-access
failures and two checked-strncpy failures. MAC27's 28 total TAG outcomes also
include two cases already rejected by RADIX_ONLY through a different category.
Do not call all 28 TAG rows additional prevented bugs.

Representative stack/heap character-copy loops (IDs 32 and 138) copy 100 bytes
into a 50-byte object in a 64-byte protected slot. MAC27 traces stop at the
original one-byte store with TAG; RADIX_ONLY returns. This supports the intended
authentication contribution: a fitting access whose derived slot changes must
not inherit the old pointer's authority. It also exposes the precision limit:
the writes into padding at offsets 50–63 precede the slot-edge rejection.

This is paired, selected-case implementation evidence, not a population estimate
or a test of the 27-bit cryptographic guessing bound. The RADIX_ONLY return does
not by itself prove the exact same bad operation's execution; detailed paired
site/iteration attribution remains useful for a final benchmark claim.

## Explaining the 21 MAC27 returns

The following classification is supported by retained source, transformed IR,
the runtime's documented slot policy and output observations. It is not a new
instruction-by-instruction execution trace.

| Explanation | Count | IDs |
| --- | ---: | --- |
| Eleven-byte string including NUL in a ten-byte allocation, rounded to 16 | 12 | 13–16, 18–21, 129–132 |
| Index 10 in a ten-element int array: four bytes at offset 40 in a 64-byte slot | 3 | 3, 125, 223 |
| `sizeof(pointer)` equals the actual eight-byte object size on this build | 3 | 179–181 |
| Stack clearing supplies the missing terminator at index 99 | 3 | 226–228 |

The first 15 are genuine object-bound violations permitted within the rounded
slot. They are protection limitations, not unexplained MAC failures. They must
remain visible when discussing source-level memory safety.

IDs 179–181 allocate eight bytes for a double, int64_t or two-int struct. The
retained IR confirms allocation size eight and an eight-byte store or two
four-byte stores. The erroneous `sizeof(pointer)` pattern is present, but these
specific executions do not underallocate on the pinned 64-bit ABI. A Juliet
bad label alone is not an executed-overflow ground truth.

IDs 226–228 copy 99 nonzero bytes into a 100-byte stack buffer without writing
the final NUL. ENCBound clears the entire new 128-byte stack slot first. Output
has exactly 99 character events plus the two line markers, consistent with the
scan stopping at the untouched zero byte at index 99. Classify as non-triggered
overread under this layout/initialization, not as bounds-check rejection or an
observed missed out-of-slot read.

## Some rejections follow corruption

IDs 11, 12, 116 and 117 copy using the enclosing struct's size into its first
16-byte character field, overwriting a pointer field in the same allocation.
The bad copy fits the enclosing slot. All four MAC27 traces show POLICY
rejection in instrumented `printLine`, called later through the corrupted
pointer; their RADIX_ONLY counterparts also reject.

These are **detected uses of a corrupted pointer after an intra-object
overwrite**, not prevention of that overwrite. The remaining rejection sites
need full primary-operation/geometry classification before assigning a strict
original-bug prevention count. Consequently `96 / 117 = 82.1%` is only this
pilot's attributed-rejection fraction; it is not an 82.1% vulnerability-prevention
rate. Merely removing the six non-triggering/platform cases would not fix this
metric, because it would still mix different kinds of rejection.

## Interpretation and next benchmark design

The pilot gives encouraging evidence for authentication's incremental effect
and benign compatibility on the supported subset. All 117 good cases match
the baseline output digest, which supports these paths, not universal semantic
correctness or absence of false positives on other inputs.

Retain three separate reporting layers:

1. **Integration coverage:** 286 candidates, 134 predetermined exclusions,
   152 attempted, 35 build rejections, 117 matched executable cases.
2. **Source-level outcome:** original bad operation rejected, corruption followed
   by a later rejection, object violation allowed within a slot, no overflow
   triggered on this build, or unresolved crash/timeout.
3. **Mechanism behavior:** bulk range crossing, fitting access rebased into a
   different slot, region/policy rejection, padding and subobject cases.

For rebenchmarking, preserve the unmodified pilot and add separately labeled
derived tests only where needed: guaranteed slot crossings, fitting cross-slot
accesses and deterministic unterminated reads. Test power-of-two boundary sizes
and bulk versus scalar-loop accesses; pair RADIX_ONLY and MAC27 at the same
observed access. Deduplicate underlying patterns when summarizing breadth and
then add selected flow variants/optimization levels. Do not alter original
Juliet sizes or initialization and still label the results unmodified Juliet.

This analysis performs no additional benchmark executions. Hardware isolation,
performance, temporal safety and exact
object bounds remain outside these pilot results.
