# Crust selected incomplete-transfer SDK SIM integration — 2026-10-23

Completed the owner's requested continuation through integration after
stubbing/removing restore. The adapted C01 incomplete-transfer enclave builds,
links, passes final ownership/startup/page audits, and runs matched ordinary
sessions in SDK simulation. No further mechanism or compiler change was needed.

## Scope and declared adaptations

The selected application is `crustio/crust-sworker` revision
`a109e0a60a4ea256d884fde192b06b025e8bd6b1`. The runner verifies all seven
source/header/EDL/license identities in [pins.json](../apps/crust-selected/pins.json)
against `git show`. Extracted build sources retain the original GPLv3 LICENSE.
The exact original `ecall_safe_store2` body has SHA-256
`235991fbafed98c157c6b43c47707aac01149ce796b01b467821d6105c1c7603`.
Its allocation, buffer-pool storage/reuse, input copy, dispatch and cleanup code
are unchanged. The two maps and mutex initializer are also retained, with the
dispatch initializer in a separate translation unit and minimal source includes.

The owner's two explicit adaptations are:

- Original `SafeLock.cpp` consumes the shared application-only serial mutex
  redirect through a wrapper translation unit. Lock/unlock return success
  without pointee access. SDK/runtime mutexes and compilation are untouched.
- Application-owned `ecall_restore_from_upgrade` calls `abort()` through the
  existing no-exception terminal adapter. The original dispatch map retains its
  address. Workload, identity restoration, JSON and ECC verification are omitted;
  the callback never reports successful restore or accesses its arguments.

The selected EDL retains the exact upstream `ecall_safe_store2` declaration.
An instrumented application snapshot ECALL copies known finite test buffer
contents and returns pool size; it exports no pointer or minting service. Two
trusted test diagnostics report region isolation and nested-gate rejection.
They are not admitted as application-callable services. Pinned SDK-only
`sgx_tstdc.edl` imports retain their SDK ownership; there are no selected
application OCALLs.

The generated C type header extracts the exact upstream `ecall_store_type_t`
definition and includes original `CrustStatus.h`. The full original
`Parameter.h` still serves application C++. This avoids duplicate C definitions
of its unrelated `SRD_LENGTH` and `FILE_ITEM_LENGTH` constants in host/bridge
units; it changes no transport enum or application type.

## Reproduction and fresh closure

```sh
python3 apps/crust-selected/run.py
```

Outputs use `build/crust-selected/enclave-v1/all-compat-v1/`. The runner builds
workload-local pass/generator binaries and prepares an isolated private-libc++
source/header tree, then freshly rebuilds all 26 configured library objects in
BASELINE, RADIX_ONLY and MAC27. Each profile consumes its actual application
callers for definition collection. High-base MAC27 uses the same placed library
bytes as low-base MAC27. All application/library units use C++17, frontend/
codegen O2, the complete `all-compat-v1` preset and the no-exceptions/no-RTTI ABI.

Each image links 33 application objects: 26 library objects, six selected
application units (body/pool, dispatch, redirected original `SafeLock`, shared
mutex, terminal restore, snapshot), and the common application errno provider.
SDK libraries, generated bridge, platform/runtime, C++ checked services/lifecycle
adapters and the two diagnostic units remain trusted and uninstrumented.

The [closed inventory audit](../apps/crust-selected/audit.py) verifies actual
application definitions/private ABIs and external services, every retained
compilation/placement/input hash chain, matching preset/profile markers,
bridge inputs/outputs, exact SDK archive hashes and absence of application/SDK
definition overlap. The existing generic final audit establishes application
global-slot geometry, metadata/ownership, page permissions and trusted-region
separation for both unsigned and signed images. Protected SDK initializer
ordering places the trusted bootstrap first. No raw mutex or real-restore
reference survives the application object closure. BASELINE's four generated
Intel bridge files are byte-identical to stock generator output.

SDK configuration retains one TCS, binding policy 0, 1 MiB stack, 2 MiB trusted
heap, 16 MiB protected application arena and 32 MiB reserved memory. The signed
metadata is sized/verified for both image bases. Every protected selected ECALL
enters/releases the trusted serial gate, including diagnostics. A diagnostic
invoked through its real bridge confirms a nested admission attempt fails
while the current invocation remains active. BASELINE uses stock SDK bridges,
one TCS and the serial finite host; no concurrent/reentrant workload is claimed.

The build/link/sign and audit scaffold derives from the repository's STL service
and SGX-KMS integration recipes. The loaded-page checker uses their ELF plus
`/proc/self/maps` method and verifies text RX, application RO/RELRO read-only and
mutable/global/metadata pages RW without execute permission. Private-libc++
licenses/origin are recorded [separately](../apps/libcxx/PROVENANCE.md), with
original notices and `LICENSE.TXT` retained in prepared build sources. New
snapshot, host, serial diagnostic and runner/audit code are local code.

## SDK simulation results

| Configuration | Ordinary ECALLs | Snapshots | Compared bytes | Retained buffers | Separate terminal completion |
| --- | --- | --- | --- | --- | --- |
| BASELINE, `0x40000000` | 90 | 44 | 22,016 | 3 | Expected SIGILL; traced |
| RADIX_ONLY, `0x40000000` | 90 | 44 | 22,016 | 3 | Expected SIGILL; traced |
| MAC27, `0x40000000` | 90 | 44 | 22,016 | 3 | Expected SIGILL; traced |
| MAC27, `0x140000000` | 90 | 44 | 22,016 | 3 | Expected SIGILL; traced |

The four independent finite host sessions pass 360 ECALLs and 176 snapshots,
comparing 88,064 bytes against host-maintained expected arrays. They exercise:

- Zero-length input with NULL; one-byte and 4,095-byte chunks; initial zeroing
  and retained unwritten bytes.
- A first 256-byte allocation followed by a larger declared total (4,096),
  with a safe in-allocation update. Preserved old bytes and pool size establish
  reuse without exposing pointer values.
- Thirty-two repeated same-key writes and interleaving of three independent
  retained buffers of 256, 1,024 and 4,096 bytes.
- A 32 MiB allocation attempt beyond both configured capacities, returning
  `CRUST_MALLOC_FAILED` with no new pool entry; existing buffers remain intact.
- Copied-buffer pointer-range overflow returning Intel's
  `SGX_ERROR_INVALID_PARAMETER`, followed by valid calls and unchanged snapshots.
- Actual loaded-page permissions, region isolation, and serial admission
  diagnostics before/after the session.

All successful store calls remain incomplete. A separate process per
configuration supplies a one-byte completing transfer through the original
ECALL. Four debugger traces stop at `ecall_restore_from_upgrade` and then show
`ecall_safe_store2 → ecall_restore_from_upgrade → encbound_cxx_fail → SDK abort`
ending in SIGILL. This is intentional terminal completion behavior, not an
ENCBound spatial rejection or evidence that original restore works.

The [machine record](2026-10-23-crust-selected-integration.json) retains the
matched results, commands/return codes/log hashes, source and tool inputs,
signed-image/link-map/inventory identities, bridge/metadata identities and
completion debugger records. Earlier
[object/native-stub evidence](2026-10-23-crust-terminal-restore.md) and
[mutex evidence](2026-10-23-shared-serial-mutex.md) keep their original
configurations and evidence classes.

## What remains outside this result

The adapted serial incomplete-transfer integration is established in SDK SIM.
The hostile two-call C01 write has not been executed or attributed, and no
protection result is inferred from builds, ordinary sessions or terminal stub
behavior. The original successful-restore path, full worker/HTTP/chain/IPFS
deployment, C02 spacex replication, hardware and performance remain unevaluated.

Incomplete transfers retain application buffers by design. The terminal stub
prevents the original cleanup after completed restore; finite sessions end by
destroying the enclave/process. Repeated-session heap exhaustion, bounded live
session cleanup, SDK SIM destructor scheduling and normal completed-transfer
cleanup are not established. The single oversized allocation failure above
does not establish an unlimited-session or general resource-recovery claim.
