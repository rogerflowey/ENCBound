# Juliet evaluation: protection results and performance status

Report date: 2026-10-11. Execution environment: **Intel SGX SDK simulation**.

ENCBound runs **129 Juliet cases in all three configurations**, with matching
good-case outputs. For the bad variants, RADIX_ONLY produces **82 attributed
check rejections** and MAC27 produces **108**. The **26 additional MAC27
rejections are authentication failures**, providing paired evidence of the
MAC's contribution on this selected dataset.

These measurements establish protection behavior and integration coverage.
**Juliet runtime overhead has not been measured.** This report consolidates
the existing execution evidence; it adds no new benchmark runs.

## Experiment setup

| Item | Configuration |
| --- | --- |
| Dataset | Pinned Juliet C/C++ 1.3 archive; C cases only |
| Candidate scope | All 286 single-file `_01.c` cases in CWE-121/122/124/126/127 |
| Platform | Intel SGX SDK 2.26 SIM, debug enclave, one TCS |
| Application compiler | Clang/LLVM 21, frontend O0 and code generation O0 |
| Trusted runtime | GCC O0 |
| Execution | One fresh process/enclave per case, variant and profile |
| Matched test set | 129 cases × good/bad × 3 profiles = 774 execution rows |
| Attribution | Protected SIGILL runs are repeated under GDB in a fresh enclave/key |
| Current evidence | [129-case run](../../evidence/juliet-2026-10-11/summary.json) |

The three configurations use the same original case bodies and requested
lengths:

| Profile | Behavior | Comparison purpose |
| --- | --- | --- |
| BASELINE | Ordinary SDK pointers and allocation; no ENCBound instrumentation | Reference execution and good-output oracle |
| RADIX_ONLY | Protected allocation slots and checks, without MAC authentication | Effect of bounds/region enforcement |
| MAC27 | Same protected mechanism, with 27-bit pointer authentication | Additional effect of authentication |

This is an enclave SDK integration: case functions and output helpers are
instrumented application code; runtime, SDK and diagnostic bridges are trusted.
It is not a native execution result or an SGX hardware-isolation result.

## Dataset coverage and integration

| Selection stage | Cases |
| --- | ---: |
| Candidate inventory | 286 |
| Predetermined exclusions | 134 |
| Attempted in each profile | 152 |
| Compile in all three profiles | 129 |
| Remaining compile failures in all profiles | 23 |

The pilot excludes wide-character filenames and cases selected by the external
or random-input filename filter. The exact filter and header adaptations are
in the [reproduction guide](README.md). Common-build coverage is
129/152 = **84.9% of attempted cases**. This is not coverage of the full Juliet
suite or of all instances of these weaknesses.

The latest extension resolved twelve ENCBound admission failures: six `strncat`
cases and six calls of exactly `snprintf(dst, n, "%s", src)`. Checked library
adapters preserve the original arguments and lengths. General variadic
formatting remains unsupported. See the
[adapter implementation and validation record](../../evidence/2026-10-11-juliet-adapters.md).

The remaining failures are SDK interface compilation issues:

| Reported undeclared functions | Cases |
| --- | ---: |
| `strcpy` | 15 |
| `strcat` | 6 |
| Both `strcpy` and `wcscpy` | 2 |

They also fail BASELINE and are excluded from the runtime denominator. They
are neither protection successes nor observed runtime failures. Repairing their
SDK interfaces would still require checking ENCBound admission and behavior.

## Good-case compatibility

All **129 good variants return normally in each profile**. Both protected
profiles match BASELINE on output-event count and digest for every case:
**258/258 protected good executions match**.

The output oracle reads strings and struct fields through instrumented
application code, then hashes emitted scalar events. It compares the adapted
output observations, rather than preserving the upstream print formatting.
No false rejection or output mismatch was observed on these good inputs; this
does not establish semantic equivalence for every possible input.

## Bad-case outcomes

| Observed outcome | BASELINE | RADIX_ONLY | MAC27 |
| --- | ---: | ---: | ---: |
| Attributed ENCBound check rejection | 0 | 82 | 108 |
| Normal return | 76 | 45 | 21 |
| Unattributed signal | 53 | 1 | 0 |
| Timeout | 0 | 1 | 0 |
| Total | 129 | 129 | 129 |

An attributed rejection requires a terminal `encbound_abort`, its diagnostic
code, the selected Juliet function and ECALL frames, and access-check arguments
or the specifically supported checked-library frame. A crash or SIGILL alone
does not count as protection. A normal bad-case return does not prove that the
original fault executed or that the execution was memory-safe.

The attributed-rejection fractions are **63.6% for RADIX_ONLY** and **83.7% for
MAC27**, using all 129 matched bad cases as the denominator. These are observed
rejection fractions, **not vulnerability-prevention rates**: some rejections
occur after corruption, some violations fit within rounded slots, and some
source patterns do not trigger an overflow on this build.

### Breakdown by weakness category

| Category | Attempted | Common builds | RADIX_ONLY rejections | MAC27 rejections | MAC27 returns |
| --- | ---: | ---: | ---: | ---: | ---: |
| CWE-121: stack buffer overflow | 67 | 56 | 37 | 47 | 9 |
| CWE-122: heap buffer overflow | 40 | 34 | 21 | 26 | 8 |
| CWE-124: buffer underwrite | 16 | 13 | 10 | 13 | 0 |
| CWE-126: buffer overread | 13 | 13 | 6 | 9 | 4 |
| CWE-127: buffer underread | 16 | 13 | 8 | 13 | 0 |
| Total | 152 | 129 | 82 | 108 | 21 |

The unresolved RADIX_ONLY timeout is stack-overflow case **6**; its SIGSEGV is
underwrite case **198**. MAC27 rejects both with TAG errors. The categories are
the dataset's labels; related templates are not independent vulnerability samples.

## What authentication adds

Pairing the same 129 bad cases gives:

| RADIX_ONLY outcome | MAC27 outcome | Cases |
| --- | --- | ---: |
| Attributed rejection | Attributed rejection | 82 |
| Normal return | Attributed rejection | 24 |
| Timeout | Attributed rejection | 1 |
| SIGSEGV | Attributed rejection | 1 |
| Normal return | Normal return | 21 |

All **26 additional rejections** have TAG code 5. This is a **20.2 percentage
point increase in the observed rejection fraction**. MAC27 has 28 TAG rejections
in total; two correspond to cases that RADIX_ONLY already rejects through
another check category and therefore are not additional rejections.

In representative scalar-copy cases **32 and 138**, the program copies 100
bytes into a 50-byte object rounded to a 64-byte slot. A one-byte access can
fit within a different inferred slot after pointer arithmetic crosses the
original slot. MAC27 rejects the changed slot identity; RADIX_ONLY returns.
Writes into padding at offsets 50–63 can precede this rejection. The
[source/IR/trace interpretation](../../evidence/2026-10-11-juliet-interpretation.md)
explains this distinction. This experiment does not measure the probability
of successfully guessing a 27-bit tag.

### Where checks reject

| Check classification | RADIX_ONLY | MAC27 |
| --- | ---: | ---: |
| RANGE | 68 | 68 |
| POLICY | 14 | 12 |
| TAG | 0 | 28 |
| Total | 82 | 108 |

RADIX_ONLY has 60 rejections at instrumented accesses and 22 in checked library
adapters; MAC27 has 84 and 24 respectively. These describe enforcement sites,
not automatically the location of the first source-level error.

All twelve newly supported bad cases reject in **both** protected profiles.
Their adapters validate a 99- or 100-byte write into a 64-byte slot and abort
before the append/format copy. They strengthen checked-library coverage, while
the incremental MAC contrast remains 26 cases.

## Remaining protection limits

The 21 MAC27 returns have the following interpretation from source, retained
IR, slot policy and observed output:

| Explanation | Cases | Interpretation |
| --- | ---: | --- |
| Source-object overflow remains inside rounded slot | 15 | Genuine precision limit of slot bounds |
| `sizeof(pointer)` equals the needed eight-byte object size on this ABI | 3 | Faulty source pattern does not underallocate here |
| Required stack clearing supplies the missing terminator | 3 | Labeled overread does not trigger under this initialization |

Separately, cases **11, 12, 116 and 117** corrupt a pointer field inside the
same enclosing struct before a later POLICY check rejects use of that pointer
in `printLine`. They demonstrate detection of a corrupted-pointer use, not
prevention of the preceding intra-object overwrite.

Full case-by-case attribution of the first faulty operation remains unfinished.
Exact object/subobject bounds, temporal safety, valid-capability reuse and
hardware isolation are not established by these results. The original 117
cases keep their earlier outcome categories in the expanded run; nine returning
bad rows have changed output digests, retained in the
[comparison record](../../build/juliet/pilot-2026-10-11-adapters/adapter-comparison.json).

## Runtime performance status

| Metric | Juliet measurement status |
| --- | --- |
| Execution time / throughput | Not measured |
| RADIX_ONLY / BASELINE slowdown | Not measured |
| MAC27 / BASELINE slowdown | Not measured |
| MAC27 / RADIX_ONLY incremental cost | Not measured |
| Peak memory or allocation-metadata cost | Not measured |
| Comparative code size | Not analyzed in this report |
| Hardware overhead | Not measured |

The current harness records outcomes, output digests and diagnostic traces,
not latency samples. It creates a fresh enclave for each tiny case and uses
scalar output OCALLs, so any future timing needs to identify those costs
explicitly. Crashes, timeouts and early rejections also perform different work
from completed executions; their durations cannot be pooled into a normal
application slowdown metric.

A future Juliet timing experiment should use matched good paths with verified
outputs, separate startup from repeated execution, retain warm-up and repeated
samples, and report the three ratios above under identical compiler settings.
Repeated execution would need a checked lifecycle and cleanup contract for
these cases; it is not a feature of the current one-shot pilot. Fault-rejection
latency would be a separate metric. The existing
[general C kernel timings](../../evidence/2026-10-11-general-benchmarks.md) concern
different workloads and must not be reported as Juliet overhead.

## Reproduction and evidence

From the repository root, with the pinned archive and SDK installation:

```sh
python3 tests/juliet/oracle_test.py
python3 tools/juliet.py --archive build/juliet/download/juliet-1.3.zip \
  --output build/juliet/juliet-reproduction
```

The output directory must not already exist. See the
[setup guide](README.md) for dependencies, archive hash, support
adaptations and configuration options. A reproduction measures its own source
state; the retained run's input snapshots identify the implementation used here.

The current primary records are the
[summary](../../evidence/juliet-2026-10-11/summary.json),
[all execution rows](../../build/juliet/pilot-2026-10-11-adapters/results.jsonl),
[CSV](../../build/juliet/pilot-2026-10-11-adapters/results.csv),
[case selection and build failures](../../build/juliet/pilot-2026-10-11-adapters/selection.json),
and [input/tool/artifact identities](../../build/juliet/pilot-2026-10-11-adapters/identity.json).
Per-row logs and debugger traces live beside those records. The
[adapter evidence](../../evidence/2026-10-11-juliet-adapters.md) records artifact hashes
and passing compiler/native/oracle checks. Earlier
[pilot](../../evidence/2026-10-11-juliet-pilot.md) and
[interpretation](../../evidence/2026-10-11-juliet-interpretation.md) documents preserve
the 117-case history; their old denominator should not be mixed with this report.
