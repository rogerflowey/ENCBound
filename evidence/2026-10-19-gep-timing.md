# Retained GEP timing follow-up

Date: 2026-10-19. Owner request: “check: any overhead improvement?”

**No material overall MAC27 speedup is demonstrated.** In two matched SDK SIM
passes, all seven configurations' five-kernel geometric-mean MAC27 time changes
are between **1.79% faster and 0.58% slower**. The existing loop fast paths with
SipHash improve by only **0.26–1.24%**; AES-CMAC is essentially flat. These small
aggregate changes are within the observed run variation. Individual kernels
have larger, repeatable gains and regressions.

This is a separate timing experiment after the
[compiler/correctness comparison](2026-10-19-retained-gep.md). Its one/three-iteration
correctness runs were not used as timing evidence. No pass, runtime, protection
check or application implementation changed for this measurement.

## Matched measurements

Compare the preserved integer-GEP-lowering builds (`lower`) with the default
retained scalar GEP builds (`plain`, flags cleared). Post-InstCombine stays off.
Use the existing validated binaries from all seven optimization configurations,
each in BASELINE, RADIX_ONLY and MAC27: **42 builds**. The five kernels are lists,
heapsort, ATAX, GEMM and Jacobi, with the existing independent reference outputs.

Changes below are **100 × (new time / old time − 1)**, using the geometric mean
of the five per-kernel median-time ratios. Negative means faster. These are time
changes, not percentage-point changes in overhead versus BASELINE.

| Configuration | MAC27, round 0 | MAC27, round 1 | RADIX_ONLY, round 0 / 1 |
| --- | ---: | ---: | ---: |
| Per-access checks | +0.36% | +0.12% | −3.33% / −2.53% |
| Block reuse | +0.58% | −0.69% | +0.85% / −0.19% |
| Loop reuse | −1.79% | +0.23% | +0.74% / −3.04% |
| Loop reuse + local proofs | −0.61% | −0.92% | +0.06% / +0.69% |
| Inline guards + local proofs | −0.44% | −0.42% | −1.58% / −1.91% |
| Loop fast paths + proofs, SipHash | −1.24% | −0.26% | −0.42% / +1.43% |
| Loop fast paths + proofs, AES-CMAC | +0.19% | +0.05% | +0.56% / +0.18% |

The largest useful examples are localized:

- RADIX_ONLY lists with per-access checks is **10.46% / 12.81% faster**.
  The same MAC27 row is **0.82% faster / 0.20% slower**.
- With inline guards, MAC27 Jacobi is **10.08% / 8.15% faster**, while GEMM is
  **8.66% / 6.78% slower**. Their effects largely cancel in the aggregate.
- With SipHash loop fast paths, MAC27 ATAX is **4.05% / 3.15% slower**, while
  GEMM is **3.70% / 1.88% faster**.

There is no broad timing result for InstCombine because the earlier whole-corpus
experiment fails compilation/validation. Original-GEP-flags timing is also not
established here.

## Code size

The exact executable-byte counts of the six application objects (driver plus
five kernels) show a tradeoff. RADIX_ONLY and MAC27 have the same application
code sizes; their separately compiled trusted checking cores differ by profile.

| Configuration | Old application text | Retained-GEP text | Change |
| --- | ---: | ---: | ---: |
| Per-access checks | 14,611 B | 14,102 B | −3.48% |
| Block reuse | 17,504 B | 16,978 B | −3.01% |
| Loop reuse | 17,715 B | 17,151 B | −3.18% |
| Loop reuse + local proofs | 17,458 B | 16,873 B | −3.35% |
| Inline guards + local proofs | 28,532 B | 30,578 B | +7.17% |
| Loop fast paths + proofs, either MAC | 32,625 B | 35,604 B | +9.13% |

BASELINE application text stays **5,997 B**, with identical executable bytes
and symbolic relocations across the old/new builds. Matched trusted objects
and host executable identities also agree. These application-text totals are
not whole signed-image sizes or memory-overhead measurements.

## Protocol, validation and limits

The scoped runner reuses the existing benchmark `Session` and full-output
oracle. It hashes the retained images against the earlier build manifest,
checks inventory/object identities, identical sources/settings/references,
matching trusted and BASELINE code, and equal security/allocation diagnostics.
All inputs are verified again after timing. An independent check recalculates
every median from the CSV and checks row counts, common repeats, all raw
correctness events, host identities and artifact manifests.

Both rounds use CPU affinity 0, one active sample at a time, six persistent
variant/profile processes per workload, five warmup batches and 30 measured
batches. Initial order reverses in round 1; each batch rotates the six rows.
Calibration uses the same repetitions in all six rows, aiming for 1 ms in the
fastest and capping the slowest near 200 ms. There are **12,600 measured batches**
and **16,380 successful full-output checks** including pilots/warmups. Creation,
first calls and destruction are separately retained and excluded from the
steady-state statistics.

Timing uses the host monotonic clock around one ECALL batch, including scratch
allocation/free, initialization, kernel work and result stores. Reference
comparison is outside the timed interval. Compiler settings are frontend O2,
backend O2, trusted O2/fused, host O0, FP contraction off and a debug enclave.
MAC keys remain fresh; no profiler/debugger is attached during timing.

The machine is an Intel Core Ultra 9 285H under WSL2
`6.18.33.1-microsoft-standard-WSL2`. Frequency policy is unavailable and competing
host load is uncontrolled. Pinning a WSL vCPU does not isolate a physical host
core. Short BASELINE batches and scheduling outliers remain: for example, round
1 per-access GEMM's identical BASELINE code differs by **19.52%** between medians,
with overlapping wide p10/p90 ranges. Aggregate BASELINE changes span
**−4.47% to +1.60%** across the mode/round pairs. This prevents interpreting
sub-percent overhead-ratio changes as a compiler improvement. The report uses
direct old/new protected-time comparisons and retains all noisy samples.

These are bounded SDK simulation measurements. No SGX hardware, EPC behavior,
full-application speedup, memory improvement or universal compiler performance
claim is established. No experiment gate is promoted.

## Reproduction and retained evidence

After the source rebuilds/oracles described in the preceding compiler record:

```sh
python3 experiments/gep-policy/measure.py --out build/gep-study-2026-10-19/timing-round0 --round 0
python3 experiments/gep-policy/measure.py --out build/gep-study-2026-10-19/timing-round1 --round 1
```

The runner refuses existing output paths; use fresh names for another run. Both
directories retain context, CSV samples, raw host events, lifetime data,
per-kernel median/p10/p90 statistics, geometric means, executable sizes, source
copies, input hashes and output manifests. Input manifests identify the exact
validated binaries and diagnostics. `timing-verification.json` records the
independent checks. The durable [JSON record](2026-10-19-gep-timing.json) contains
both rounds' results/context, source hashes and manifest identities.
