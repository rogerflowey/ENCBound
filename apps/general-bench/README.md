# Preliminary general C benchmarks

Fresh three-profile **active heap memory** measurements are available with:

```sh
python3 apps/general-bench/memory.py --out build/memory-UNIQUE
python3 tests/general_bench_memory_test.py --run build/memory-UNIQUE
```

The runner creates fresh audited builds with the historical benchmark settings
(O2 frontend/backend, O2/fused runtime, SipHash, reuse/proofs/fast paths off),
then checks full outputs during one and three iterations in each profile.
It needs local GDB/ptrace access. Read-only debugger observations count BASELINE's
actual SDK malloc chunks and protected rounded slots plus actual SDK chunks for
buddy metadata and arena activation. The latter retains 32 SDK descriptors,
2 KiB in this pinned build, after workload cleanup. These are explicitly
attributed SDK instance costs, not leaked application allocations.

The report separates requested bytes, padding, metadata payload/chunks, retained
startup storage, configured capacities and ELF load-segment bytes. It excludes
stack high-water, free-space fragmentation, pre-entry SDK allocations and resident
EPC pages. These kernels have no writable globals; the all-compat preset and
protected-global costs are not measured. Logs, raw allocation events, binaries,
source snapshots and hashes are retained; debugger timings are not results.
See [results and exact definitions](../../evidence/2026-10-20-memory-overhead.md).

Five pinned kernel adaptations under Intel SDK simulation, BASELINE/RADIX_ONLY/
MAC27. See [PROVENANCE.md](PROVENANCE.md) for source licenses, custom dimensions,
the deferred hash candidate, exact adaptations and correctness oracles.

The optional `MAC_ALGORITHM=aes128_cmac` / runner `--mac-algorithm aes128_cmac`
uses full AES-NI CMAC with a private per-instance schedule and MSB27 tags in
MAC27. Default is `siphash24`; BASELINE/RADIX_ONLY remain MAC-free. AES builds
reject hosts lacking AES-NI before entering the enclave. Algorithm identity is
recorded in build stamps and inventories. For the matched six-row comparison,
use `tools/compare_general_bench.py --study mac` on retained `siphash24` and
`aes128_cmac` run directories, both with `--check-reuse loop --fast-paths loops`.
See [results and reproduction](../../evidence/2026-10-13-aes-cmac-runtime.md).

Prerequisites are the restart's pinned LLVM 21/SDK 2.26 environment, patched
edger8r build dependencies, Python 3, binutils, make, gdb and taskset. The recipe
uses frontend O2, optional tested codegen O2 (default here), FP contraction off,
and O2 trusted code with the fused checking core (defaults for this benchmark).
The host remains O0; SDK libraries are pinned prebuilt archives. The enclave
retains debug attributes. The recipe accepts only SIM/debug1;
it is not a release-build or hardware performance report.

From the repository root:

```sh
make -C apps/general-bench PROFILE=MAC27
python3 apps/general-bench/run.py --out build/general-bench-run-UNIQUE
```

The runner refuses an existing output directory. It builds/audits all profiles,
generates independent references, runs native correctness controls and debugger
security/allocation diagnostics, then measures 30 batches after five warmups.
Each profile remains in its own process/enclave for that workload, with one active
process at a time; profile order rotates per batch. A single ECALL repeats the
workload a common number of times, including initialization, kernel calls,
scratch allocation/free and result stores. Marshaling occurs once per batch.
Host timing is monotonic; result checking and reporting occur after timing.
Creation, first request and destruction are recorded separately.

Calibration aims at 1 ms for the fastest profile while limiting the slowest
to about 200 ms. With very large overhead, baseline batches may be shorter than
1 ms; raw batch durations, repeats and spreads remain available. This is a
practical preliminary protocol, not a fixed 200 ms baseline-duration claim.
Do not interpret amortized batch time as an isolated kernel clock or a normal
one-operation request latency.

To select a CPU, SDK location or independent build directory:

```sh
python3 apps/general-bench/run.py --out build/general-bench-fresh-UNIQUE \
  --build-root build/general-bench-fresh-build --cpu 0 \
  --sdk /path/to/sgxsdk --codegen=-O2
```

Choose a CPU from the process's allowed affinity set (the default does this).
`PINNED_SRC` can be set through the environment/make for the pinned SDK internal
headers. Network is not needed: upstream bytes and licenses are vendored. The
runner retains samples.csv, summaries, context, source snapshots, references,
host/unsigned/signed binaries, application IR/objects, link maps and hashes.
Private signing keys stay in build directories and are not copied into evidence.

Debugger diagnostics corrupt the existing ATAX input capability at kernel entry:
slot-end straddle, one flipped tag bit, and a stripped raw pointer. The oracle
requires the injected bits, exact entry, abort argument register, checked
pointer/width/kind, kernel/check stack and terminal SIGILL. It does not infer
protection from a crash alone. RADIX_ONLY's tag-bit control must produce the full
correct output. This is a diagnostic debugger experiment, not an app input attack.

Memory diagnostics inspect the actual sparse tree at every successful public
allocation/free return over one then three iterations. They report requested and
rounded peaks including boundary output storage, dynamic node payload, pair
allocation/free counts and zero final live state. SDK allocator headers,
fragmentation and stack high-water are not measured. These debugger runs supply
no timing results. The unchanged capacities are a 16 MiB arena, 2 MiB trusted
SDK heap, 1 MiB stack and 32 MiB committed reserved region.
The newer `memory.py` route above additionally measures SDK chunk overhead and
retained arena-startup storage in a fresh matched three-profile experiment.

Harness regression checks (after one measurement run):

```sh
python3 tests/general_bench_test.py --run build/general-bench-run-UNIQUE
```

The trusted-core optimization compiles the existing SipHash, runtime state and
capability sources together, allowing private helpers and the same six-byte
SipHash body to inline. Application code remains separately instrumented; no
application/runtime LTO, check hoisting, MAC cache or authentication elision is
used. Other application/SDK Makefiles retain their existing defaults.

For the controlled optimization comparison, use fresh output/build roots:

```sh
python3 apps/general-bench/run.py --out build/runtime-study/o0 \
  --build-root build/runtime-study/build-o0 --trusted-opt=-O0 --trusted-core=separate
python3 apps/general-bench/run.py --out build/runtime-study/o2 \
  --build-root build/runtime-study/build-o2 --trusted-opt=-O2 --trusted-core=separate
python3 apps/general-bench/run.py --out build/runtime-study/optimized \
  --build-root build/runtime-study/build-optimized --trusted-opt=-O2 --trusted-core=fused
python3 tools/compare_general_bench.py --runs-root build/runtime-study \
  --out build/runtime-study/interleaved
python3 tests/runtime_optimization_test.py --out build/runtime-study/native-tests
```

The comparison verifies retained artifact manifests and identical source/input
snapshots, then rotates all nine variant/profile rows with identical repetitions
per workload. This gives 1,350 measured batches, separate from each input run.
`TRUSTED_OPT=-O0|-O2` and `TRUSTED_CORE=separate|fused` select the same options
when invoking make directly. Default paths include both options; a configuration
stamp also forces rebuilding if an explicit BUILD directory is reused.

Optional software PC profiling of an already validated run (never use its times
as performance samples):

```sh
python3 tools/profile_general_bench.py --run build/runtime-study/optimized \
  --out build/runtime-study/profile-mac --profile MAC27 --case gemm
```

It uses `perf`'s `cpu-clock:u` sampling and resolves the SDK's anonymous enclave
mapping against the retained ELF at the verified base. This is statistical
instruction-pointer attribution, not hardware cycles or dynamic call counts.

Native is a correctness control only. SIM has no SGX hardware isolation or EPC
performance claim. These supplemental cases do not complete gates A–E or the
unfinished standalone LZ4 integration.

Optional guarded check reuse is selected by `CHECK_REUSE=block|loop` (make) or
`--check-reuse=block|loop` (runner). Default `off` retains the per-access full
check. Block mode shares slot validation among multiple scalar accesses in a
call/volatile-free block segment. Loop mode also prepares invariant slot anchors
in eligible loop preheaders. Every access retains a full-capability range guard
and the original full-check fallback. See [step 12](../../docs/legacy/steps/12-check-reuse.md).
The debugger additionally corrupts pointers after successful preparation in
reuse modes. Tokens must remain compiler-private; these modes are experimental.

For a matched comparison, run all three modes into new directories named
`off`, `block`, `loop` under one runs root, then use:

```sh
python3 tools/compare_general_bench.py --study reuse \
  --runs-root build/reuse-runs-UNIQUE --out build/reuse-comparison-UNIQUE
```

This checks retained manifests, source/flag identities, correctness diagnostics
and allocation geometry before rotating all nine mode/profile combinations.

Bounded local proofs compose with reuse: `LOCAL_PROOFS=1` (make) or
`--local-proofs=1` (runner). The default is zero. This removes constant-offset
local-slot checks after minting, and same-kind scalar checks wholly covered by
an earlier check in the same barrier-free block. Uncertain ranges retain checks;
it does not remove guards from whole loops. See [step 13](../../docs/legacy/steps/13-local-proofs.md).
Use `--study proofs` for a comparison with run subdirectories `off` (reuse off,
proofs 0), `loop` (reuse loop, proofs 0), `proofs` (reuse loop, proofs 1).
