# Memory overhead: fresh matched SDK simulation measurements

The owner asked whether ENCBound's memory overhead can be measured. A new
read-only debugger runner measures **active heap storage** in the five existing
general C kernels against actual BASELINE SDK allocator chunks. Overhead ranges
from **2.19% to 133.76%**, including the SDK bookkeeping activated by the protected
arena. RADIX_ONLY and MAC27 have identical heap peaks and allocation counts.
These are SDK SIM results, not total resident enclave-memory or EPC overhead.

## Results

Every value below is bytes. The protected total is a concurrent observed peak:
rounded live slots plus live trusted SDK chunks, including startup storage.
The bridge output buffer is included in all profiles.

| Kernel | Requested peak | BASELINE SDK chunks | Protected slots | Buddy metadata SDK chunks | Retained SDK startup | Protected total | Overhead vs BASELINE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| lists | 4,880 | 4,976 | 8,240 | 1,344 | 2,048 | 11,632 | 133.76% |
| heapsort | 65,544 | 65,584 | 98,304 | 576 | 2,048 | 100,928 | 53.89% |
| ATAX | 134,144 | 134,208 | 134,144 | 960 | 2,048 | 137,152 | 2.19% |
| GEMM | 55,296 | 55,344 | 98,304 | 640 | 2,048 | 100,992 | 82.48% |
| Jacobi | 65,536 | 65,568 | 65,536 | 576 | 2,048 | 68,160 | 3.95% |

The buddy metadata payloads are respectively 1,008, 432, 720, 480 and 432 bytes.
Actual SDK chunks include allocator headers/footer and alignment: each 48-byte
node pair occupies a 64-byte chunk in this build. The static 24-byte tree root is
reported separately and included in the loaded image, not the dynamic heap.

The 2,048-byte startup charge comprises **32 SDK reserved-memory descriptors**,
each requested as 48 bytes by `init_vrdl` and charged as a 64-byte chunk. ENCBound's
first arena activation invokes this SDK subsystem. Tracing attributes these
allocations separately from `allocate_node`; no other SDK allocation caller is
admitted by this scoped observer in protected rows. These descriptors remain
until enclave destruction. All application slots and buddy metadata are freed.
BASELINE does not activate this reserved-memory subsystem in this workload.

Excluding the fixed startup charge, workload heap overhead is 92.60%, 50.77%,
0.67%, 78.78% and 0.83%, respectively. Both views are retained in the JSON;
the headline includes startup. Small workloads amplify fixed costs. ATAX/Jacobi
request power-of-two buffers; heapsort's 32,776-byte scratch buffer rounds to
65,536 bytes; GEMM's three 18,432-byte buffers each round to 32,768 bytes. These
geometries explain much of the variation. No aggregate is a universal overhead.

The incremental **heap** cost of MAC27 versus RADIX_ONLY is zero in every row.
Pointers retain their ordinary 64-bit storage width. This does not establish zero
total MAC memory cost: code, static state and stack must be accounted separately.

## Static image and configured capacity

| Quantity | BASELINE | RADIX_ONLY | MAC27 |
| --- | ---: | ---: | ---: |
| Sum of ELF PT_LOAD memory sizes | 154,912 B | 177,480 B | 178,064 B |
| Signed file size, including debug/file-only data | 261,312 B | 366,600 B | 366,432 B |
| Configured SDK stack | 1 MiB | 1 MiB | 1 MiB |
| Configured SDK heap | 2 MiB | 2 MiB | 2 MiB |
| Configured initial/max reserved memory | 32 MiB | 32 MiB | 32 MiB |
| Signer-verified enclosing range | 64 MiB | 64 MiB | 64 MiB |

The loaded-segment sum grows by 23,152 bytes from BASELINE to MAC27 and by
584 bytes from RADIX_ONLY to MAC27. It includes code, read-only data and writable
data/BSS, but excludes intersegment/page gaps and SDK runtime-added resources.
It is not the signed file size or a physical-page count.

The protected **16 MiB arena lies inside the 32 MiB reserved region**; do not add
them together. BASELINE intentionally retains the same resource configuration
for this matched experiment; the table does not imply it needs that reservation.
Equal configured capacities do not establish zero memory overhead. Unused arena
capacity, live objects, committed/reserved resources and resident pages are
different quantities. Free-space fragmentation, stack high-water and resident
EPC use remain unmeasured. No host RSS proxy is used.

## Method and validation

`apps/general-bench/memory.py` builds and audits all three profiles into a fresh
directory. It preserves the existing benchmark configuration: frontend/backend
O2, trusted O2/fused, SipHash, reuse off, local proofs off, fast paths off, debug
enclave, one TCS and base `0x40000000`. This is the historical kernel recipe,
not a new application integration using the all-compat preset. The kernels have
no writable globals; protected-global padding/table/fixup costs are not measured.

`memory_gdb.py` starts at the first trusted bridge entry, before ENCBound startup
and marshaling. Numeric breakpoints target the enclave's malloc/free definitions,
not host libc. It records allocation return values and reads pinned SDK dlmalloc
chunk headers without calling inferior functions or interposing any allocator.
The SDK's `FOOTERS=1`, 16-byte alignment and chunk mask are checked against the
pinned source; raw allocations retain their caller attribution and chunk charge.

At each successful protected allocation/free return, the observer traverses the
actual buddy tree, derives slot sizes and cross-checks every live child pair
against observed SDK allocations. Public-operation snapshots avoid temporary
unlinked nodes during splitting/coalescing. Successful allocations increase live
storage and frees decrease it, so these snapshots capture this workload's peak.
The total is maximized per snapshot, not computed by summing unrelated maxima.
BASELINE snapshots follow SDK allocation return/free entry. The observer changes
no application/runtime source or protection checks; it supplies no timing result.

Fresh final validation:

- All three closed build/ownership/SDK-pin audits pass, including stock Intel
  bridge equality for BASELINE and protected application access instrumentation.
- **15 memory rows / 30 complete-output comparisons** pass against independent
  references, with one then three iterations in each fresh enclave session.
- All workload allocations and buddy metadata are reclaimed. Protected sessions
  retain only the attributed 32 SDK startup descriptors. Protected allocation
  geometry, metadata and counts match between RADIX_ONLY and MAC27.
- Six existing SDK SIM corruption controls pass: RANGE and raw-pointer POLICY
  rejections in both profiles, MAC27 TAG rejection, and the complete correct
  RADIX_ONLY output after changing only tag bits. These validate the measured
  builds' existing checks; they are not a new application security result.
- `tests/general_bench_memory_test.py` independently replays all 15 SDK event
  streams, checks every stable snapshot, computes BASELINE charges from known
  workload sizes, rejects 75 damaged evidence records, and verifies all retained
  artifact hashes. This is host-side validation, not native enclave execution.

Initial diagnostic attempts are preserved under `build/memory-overhead-2026-10-20*`.
The first sandboxed debugger launch failed because ptrace was blocked; the local
escalated run was approved. An initial observer needed the x86 return register
because the prebuilt SDK lacks return-type debug information. Its cleanup check
then exposed the retained SDK startup allocations. Caller tracing identified
`init_vrdl`; the final metric explicitly includes that cost. No allocator leak,
design change, exemption or weakened check was introduced to obtain these rows.
Earlier pilot outputs are not the final artifact.

## Reproduction and remaining work

```sh
python3 apps/general-bench/memory.py --out build/memory-NEW
python3 tests/general_bench_memory_test.py --run build/memory-NEW
```

Local debugger tracing must be permitted. Outputs are refused if the directory
already exists. The final fresh artifact is
`build/memory-overhead-2026-10-20-final-evidence/`: audited binaries, link maps,
source snapshots, per-event JSON, GDB commands/logs, result JSON and manifest.
Private development signing keys remain in build directories and are excluded
from the manifest/evidence record. The durable
[JSON record](2026-10-20-memory-overhead.json) retains results and identities.

Remaining measurements are observed stack/alignment/frame demand, application
and library workloads including protected globals/variadics, free-space
fragmentation/capacity, full SDK session memory and actual hardware EPC behavior.
The host still exposes no SGX CPU flag/device. No hardware result or gate
promotion, and no pointer mechanism, protected scope, backend, frozen target or
trusted-code boundary change is claimed.
