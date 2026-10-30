# General C benchmark implementation and preliminary performance

Date: 2026-10-11. Owner approved the six-candidate proposal and requested
implementation and tests. Five fitting kernel adaptations now run in all three
profiles; hash is deferred. This is a supplemental **SDK SIM** performance
experiment, not a completed two-application/hardware evaluation or a full-suite
score. No protection mechanism or check was weakened for timing.

## Result and interpretation

All 15 workload/profile rows pass full-output comparison. The final fresh-build
run retains **450 measured batches** (30 per row, after five warmups), plus pilots,
startup observations, native controls and separate debugger diagnostics.

Median host batch time divided by identical repetitions, in microseconds per
workload iteration:

| Workload | BASELINE us | RADIX_ONLY us | MAC27 us | RADIX/BASELINE | MAC/BASELINE | MAC/RADIX |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| lists | 0.776 | 79.721 | 221.556 | 102.71x | 285.45x | 2.78x |
| heapsort | 282.920 | 4221.498 | 11444.636 | 14.92x | 40.45x | 2.71x |
| atax | 16.560 | 1662.963 | 4733.406 | 100.42x | 285.84x | 2.85x |
| gemm | 21.194 | 3696.086 | 10068.491 | 174.39x | 475.06x | 2.72x |
| jacobi | 22.649 | 3813.955 | 11249.658 | 168.39x | 496.69x | 2.95x |

Geometric means across these five custom workloads:

- RADIX_ONLY / BASELINE: **85.31x**.
- MAC27 / BASELINE: **238.94x**, equivalent to **23,793.76% added time**.
- MAC27 / RADIX_ONLY: **2.80x**, equivalent to **180.07% added time**.

These are ratios of per-profile medians. Authentication includes capability
minting and access verification, not isolated SipHash instruction latency. The
large RADIX_ONLY cost shows substantial overhead already exists without MAC;
this experiment does not attribute that cost among range/region checks, function
calls, allocator work or lost optimization. The current trusted runtime is O0,
so this is not an estimate of a fully optimized implementation's overhead.

The first exploratory run gave a MAC/BASELINE geometric mean of 234.79x; the
fresh-build run gives 238.94x. That agreement supports the rough large-cost
conclusion, not precise universal slowdown ratios. Keep per-workload results;
five selected kernels cannot represent general application performance.

## Configuration and timing scope

- Intel Core Ultra 9 285H, x86-64 WSL2, kernel
  `6.18.33.1-microsoft-standard-WSL2`; CPU affinity 0.
- Pinned Intel SDK 2.26, Clang/LLVM 21, one TCS, debug enclave. App frontend O2,
  tested experimental codegen O2, no general post-instrumentation IR optimizer
  or LTO, FP contraction off. Trusted runtime/bridge/host remain O0/debug;
  shipped SDK archive hashes are enforced.
- Same source, dimensions, outputs, bridge interface, flags and batch repetitions
  across profiles. BASELINE's generated bridges match the stock Intel generator
  byte-for-byte. Protected profiles have identical allocation geometry/counts.
- One warmed enclave per workload/profile; profiles rotate in each measured
  batch. One ECALL contains repeated independent iterations. Scratch
  allocation/free, initialization, kernel computation and result stores are
  included. The output allocation and SDK copies occur once per batch. Full
  result comparison and logging are outside timing. There are no timing OCALLs.
- Creation, first request and destruction are separate in `lifetimes.json`.
  Amortized batch timings are not isolated compute-kernel times or single-request
  service latencies. Allocation lifetimes are the same in every profile.
- Calibration aims for 1 ms on the fastest profile, capped near 200 ms on the
  slowest. Some warmed baseline batches are shorter than 1 ms. Governor and
  frequency controls are unavailable in this WSL2 environment; competing host
  activity is uncontrolled. Context/load and all samples are retained.

The following p10–p90 ranges are also amortized microseconds per iteration.
Baseline spread is substantial in several rows; this is a rough prototype
measurement, not a claim of a narrowly determined overhead percentage.

| Workload | Iterations/batch | BASELINE p10–p90 us | RADIX_ONLY p10–p90 us | MAC27 p10–p90 us |
| --- | ---: | ---: | ---: | ---: |
| lists | 337 | 0.710–1.327 | 73.042–85.629 | 213.660–227.837 |
| heapsort | 5 | 240.163–513.551 | 3927.479–4596.109 | 11052.297–12095.802 |
| atax | 41 | 15.345–18.027 | 1606.646–1724.874 | 4694.235–4807.324 |
| gemm | 20 | 19.108–40.554 | 3588.465–3840.014 | 9876.220–10261.539 |
| jacobi | 17 | 20.585–25.137 | 3643.933–3974.130 | 11033.347–11576.501 |

No SGX device or CPU SGX flag was available in the recorded preflight. Hardware
rows are blocked by that environment. SIM has no hardware isolation/EPC timing
claim; native is only a correctness/sanitizer control here.

## Workloads, adaptation and admission

See [source provenance](../apps/general-bench/PROVENANCE.md) for the exact LLVM
revision, individual file hashes, licenses and complete adaptation recipe.

| Workload | Fixed input | Principal exercised behavior |
| --- | --- | --- |
| lists | Original SIZE=100 | Contiguous list-node arrays, pointer manipulation, equality/reversal, allocation/free |
| heapsort | 4096 doubles, original LCG seed 42 | Data-dependent indexed heap accesses |
| ATAX | 128 x 128 doubles | Matrix/vector traversal |
| GEMM | 48 x 48 doubles, alpha=1.5/beta=1.2 | Arithmetic and repeated array accesses |
| Jacobi-2D | 64 x 64 doubles, 8 time steps | Neighboring-element reads and repeated updates |

The four sorting/numerical kernel bodies are extracted verbatim. A separate
instrumented application driver replaces CLI/timing/printing and supplies
initialization and exact-size output buffers. PolyBench datasets are custom.
Lists retains its computation and every original correctness predicate, with
explicit allocation failure handling and error returns replacing print/exit.
Lists does not allocate individual nodes: its array-slot protection is not
subobject isolation between nodes. These cases are primarily heap-oriented;
register locals and compiler spills are not a broad protected-stack benchmark.

Hash's actual native-header compiler probe rejects unapproved `perror`; the
source also calls sprintf, strdup and exit. Its source declares a non-const
prime table, but the inspected O2 IR makes that table constant: **the observed
blocker is service admission**, not demonstrated failure of writable-global
support. It is deferred, with the rejection retained in
`screen/hash-admission.log` and `screen/hash.input.ll`; it is not a failed
protection test or silently removed after observing timing.

All six application objects (driver plus five kernels) pass the mandatory pass,
validator and closed object/call inventory in protected profiles. Unknown calls,
new globals and profile/domain mismatches fail visibly. The frontend-generated
read-only output-size table uses the existing per-app-object COMPAT placement;
only that application-owned data is admitted. Post-run ELF inspection finds
`.encbound.appdata` in the read-only LOAD segment in all profiles. SDK data is
not reclassified. This run uses the byte-preserving section helper fixed by the
concurrent Juliet task; its exact hash/source is retained.

## Correctness and protection checks

`reference.py` supplies independent complete outputs: Python sorting and separate
numerical loops, with original list invariants/result 100. Every measured batch
compares all live output bytes; no oracle is learned from a protected execution.

Fresh checks on the final retained images:

- Five native workloads pass ASan/UBSan and their independent outputs.
- All three SDK profiles reject deliberately corrupted reference output; invalid
  workload/count/length/NULL inputs are rejected by the native harness checks.
- Configuration negatives reject unknown profile/codegen, frontend O0, HW mode
  and a non-debug request in this explicitly SIM/debug recipe.
- Actual ATAX entry is observed with dimensions 128/128 and a live radix-17 A
  allocation. Debugger injection moves its capability to four bytes before the
  slot edge: the first checked 8-byte read aborts with RANGE in both protected
  profiles. Stripping to the raw enclave address produces POLICY in both.
- Flipping exactly one tag bit while retaining the slot/offset produces TAG in
  MAC27; RADIX_ONLY completes with the full correct output. This guaranteed
  tag-mismatch case is not a cross-slot collision experiment and does not replace
  the previous E1 test or prove cryptographic strength.
- The oracle checks the exact injected/checked pointer, entry PC, abort argument
  register, read width/kind, kernel/check frames and terminal SIGILL. Fifty
  mutations of these transcripts are rejected by harness regression tests.

These are debugger diagnostics of the actual application kernel, not natural
malicious workload inputs. Check attribution and mandatory IR verification are
bounded evidence; no universal final-machine-code mediation proof is claimed.
The existing temporal/shared-stack exclusions and 27-bit limitations remain.

## Memory and code size

Separate debugger runs inspect the actual sparse tree at successful allocation
and free returns during one then three iterations (two sequential ECALLs).
Observed protected high-water values include the bridge's output allocation:

| Workload | Peak requested bytes | Peak rounded bytes | Peak metadata payload bytes | Peak live objects |
| --- | ---: | ---: | ---: | ---: |
| lists | 4880 | 8240 | 1008 | 4 |
| heapsort | 65544 | 98304 | 432 | 2 |
| atax | 134144 | 134144 | 720 | 4 |
| gemm | 55296 | 98304 | 480 | 3 |
| jacobi | 65536 | 65536 | 432 | 2 |

RADIX_ONLY and MAC27 have equal peaks and operation counts for each workload.
Every diagnostic ends with zero live requested/rounded bytes and zero dynamic
node payload, and equal allocation/free counts. Metadata payload excludes the
24-byte static root, SDK allocator headers/alignment, fragmentation and stack
space. These costs were observed outside timing, without modifying/interposing
SDK malloc. They are not precise total enclave-memory overhead versus BASELINE.

Capacities remain: 16 MiB protected arena, 2 MiB trusted SDK heap, 1 MiB SDK stack,
32 MiB committed reserved region, 64 MiB signer-derived enclave extent. Actual
stack high-water and SDK allocator internal costs remain unmeasured; host RSS
is not substituted for either.

| Profile | App object .text* bytes | Direct trusted object .text* bytes | Whole enclave .text bytes | Signed file bytes |
| --- | ---: | ---: | ---: | ---: |
| BASELINE | 5997 | 2367 | 118284 | 248800 |
| RADIX_ONLY | 14611 | 17817 | 138956 | 309912 |
| MAC27 | 14611 | 18038 | 140748 | 314272 |

Object text sums are input-object `.text*` sizes, not a claim about individual
functions surviving linker garbage collection. Whole-image `.text` is reported
separately; other executable sections and all section sizes remain in the JSON
inventories/maps. Signed file size includes debug information and fixed SDK
content and is not live memory use. The two protected application text totals
match; runtime size and tag work differ. Static IR site counts are recorded but
are not dynamic check counts.

## Implementation and reproduction

New code is limited to `apps/general-bench` plus
`tests/general_bench_test.py`. This experiment does not edit the pass/runtime or
introduce a compatibility framework. The origin/license record, generator,
closed audit, independent references, SDK host and runner remain small and
specific to the five selected workloads.

Final reproduction from previously nonexistent build/output directories:

```sh
python3 apps/general-bench/run.py \
  --out build/general-bench-2026-10-11/final \
  --build-root build/general-bench-2026-10-11/fresh-build
python3 tests/general_bench_test.py \
  --run build/general-bench-2026-10-11/final
```

Use new directory names when repeating: the runner refuses to overwrite a run.
The [README](../apps/general-bench/README.md) documents SDK/CPU overrides and
prerequisites. Upstream sources are vendored and pinned, so this reproduction
requires no benchmark download. Test signing keys remain outside exported run
artifacts.

Primary artifacts under [the final run](../build/general-bench-2026-10-11/final/):

- [Raw samples](../build/general-bench-2026-10-11/final/samples.csv),
  [summary](../build/general-bench-2026-10-11/final/summary.json),
  [machine context](../build/general-bench-2026-10-11/final/context.json).
- Per-profile host/unsigned/signed binaries, generated bridges, application
  IR/objects, maps/inventories, native controls and independent references.
- Per-profile security/memory debugger scripts, raw logs and structured outcomes.
- Benchmark source snapshot, shared compiler/runtime/helper snapshot and a
  [317-entry SHA-256 manifest](../build/general-bench-2026-10-11/final/manifest.json).
- [20 regression-test groups](../build/general-bench-2026-10-11/final-tests/results.json)
  and [artifact verification](../build/general-bench-2026-10-11/postchecks/verification.json).

All three profiles used identical benchmark/shared source identities and all
317 retained file hashes were verified. After timing completed, another task
changed `pass/encbound_pass.cpp`, `runtime/adapters.c` and
`include/encbound_runtime.h` for additional Juliet string services. Those changes
are preserved. **These measurements describe the retained final-run snapshot;
they are not transferred to subsequently rebuilt shared code.** The runner
checks source stability during future measurements and retains each new snapshot.

## Failed attempts and remaining work

Early development attempts are retained outside `final`: an audit CLI needed
`--codegen=-O2`; exact-size output selection introduced a compiler constant table,
which the closed audit correctly rejected before its existing COMPAT treatment
was wired in. No benchmark checks were skipped to address either issue.

Initial debugger attempts lost the stack when the SIM process terminated with
SIGILL. An attempted no-pass signal setting stalled and was stopped. The final
oracle instead observes the actual abort entry/argument before terminal SIGILL.
At that entry, GDB's not-yet-initialized O0 local `code` can misleadingly display
17; the oracle uses the x86-64 argument register at the exact entry PC. Native
and transcript-negative tests validate the observation rules.

This preliminary work establishes custom five-kernel SIM cost, correctness and
listed protection checks. It does not close the frozen two-app experiment,
standalone LZ4 acceptance, general stack/resource coverage or hardware gates.
Before interpreting practical deployment overhead, a separately validated
optimized trusted-runtime experiment and real hardware measurements are needed.
No such optimization or hardware result is claimed here.
