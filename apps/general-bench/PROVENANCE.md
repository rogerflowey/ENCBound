# Source origin and adaptations

The owner authorized implementation/testing of a small general C performance
subset on 2026-10-11. These are additional performance cases, not replacements
for an application-specific protection result.

All upstream files are from llvm/llvm-test-suite commit
`624469628023f75fe320e431aaea038e23018d80`. `upstream/manifest.json` records the
exact raw URLs and SHA-256 hashes; `prepare.py` verifies every file before reuse.
The original files are retained unchanged. The repository's `LICENSE.TXT`
(Apache-2.0 with LLVM exceptions and the retained legacy license) and the
PolyBench-specific Ohio State license are included. The Shootout source headers
retain their original bagley.org attribution. Generated excerpts identify this
record; distribute the accompanying licenses with source/binary artifacts.

## Screening and fixed workloads

| Candidate | Disposition and workload |
| --- | --- |
| Shootout lists | Accepted: original SIZE=100; list construction, copy, transfers, reverse, equality and cleanup per iteration |
| Shootout heapsort | Accepted kernel: sort 4096 doubles, seed 42, original LCG constants; smaller than upstream's CLI default |
| PolyBench atax | Accepted kernel: double precision, M=N=128 |
| PolyBench gemm | Accepted kernel: double precision, NI=NJ=NK=48, alpha=1.5, beta=1.2 |
| PolyBench jacobi-2d | Accepted kernel: double precision, N=64, TSTEPS=8 |
| Shootout hash | Deferred: actual compiler probe rejects unapproved `perror`; source also requires sprintf, strdup, exit and a writable prime table. No new services/global policy admitted for this first measurement. |

Selection used mechanism fit, not observed speed. These five adapted kernels
are not a full LLVM, Shootout or PolyBench suite score. Fixed dimensions are
custom datasets; no comparison to upstream reference timing is claimed.

## Complete adaptation recipe

`prepare.py` extracts the heapsort and three PolyBench computational function
bodies verbatim. PolyBench macros resolve to fixed-size heap-array types and
the original runtime loop bounds; the functions have external linkage so the
separate instrumented driver calls them. No LTO or cross-unit inlining is used.
This differs from the upstream standalone program's possible inlining into main.

Lists retains all computational functions and every correctness predicate.
The unused printing function and CLI main are removed; failure printing/exit
becomes cleanup plus an error result. Explicit allocation-failure handling is
added equally to all profiles. Lists allocates two contiguous node arrays and
one head, not a separately allocated object per node: spatial protection is at
the array-slot level, not isolation between those subobjects.

`driver.c` replaces CLI parsing, benchmark timers and output formatting. It uses
the upstream initialization formulas. Heapsort's PRNG state is invocation-local,
reset to 42 for each independent iteration; the sorting kernel is unchanged.
The unused original PRNG helper with its writable static is not linked. The
hash table is not adapted or measured.

Each iteration initializes fresh scratch allocations and frees them afterward;
the output buffer is borrowed for the ECALL batch. ATAX y, GEMM C and Jacobi A
use that buffer directly. Output extents are exactly 8, 32768, 1024, 18432 and
32768 bytes. The modified Intel bridge allocates protected output storage in
RADIX_ONLY/MAC27; BASELINE's emitted bridge is checked byte-for-byte against
the installed stock generator. Outputs do not persist across ECALLs.

All driver/kernel objects are application code. Only the existing SDK, bridge,
boundary support, platform binding, runtime and checked libc adapters are
trusted. The frontend synthesizes one read-only output-size lookup table;
the existing per-object section tool puts only application rodata into COMPAT.
The closed audit rejects other IR globals and all writable app globals. SDK
data is not reclassified. No checks, stack initialization or admission rules
are disabled. No runtime/pass mechanism changes are made for this experiment.

`reference.py` independently computes every output element (Python sorting for
heapsort and separate mathematical loops for the numerical cases). The original
lists assertions plus the known result 100 form its oracle. Exact binary64
comparison is used with FP contraction off in all profiles. Reference generation
does not run the adapted C or learn expected results from a protected build.

These cases primarily exercise heap capabilities; optimized scalar locals may
remain in registers. They do not establish broad addressable-stack coverage.
