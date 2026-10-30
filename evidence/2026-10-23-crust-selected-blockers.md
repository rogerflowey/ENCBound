# Crust C01 selected-path integration blockers — 2026-10-23

The selected incomplete-transfer path is a bounded integration candidate, with
**two concrete unresolved dependencies: a safe SDK mutex service and the restore
dispatch reference**. No new pointer-mechanism or compiler feature requirement
was observed in the selected function. This is an assessment with fresh native
generation/object probes, not an integrated or executed Crust enclave.

## Selected scope and identity

Repository: `crustio/crust-sworker`, revision
`a109e0a60a4ea256d884fde192b06b025e8bd6b1` (C01 in the
[ingress assessment](../research/nontrivial-ingress-bugs/V2-V4-INTEGRATION.md#c01c02--crust-sworker--spacex-storage-stateful-buffer-pool)).
The source-manifest's **147/147 cached files** match their recorded SHA-256
identities. The six consumed source/header files also match `git show` at that
revision in the existing screening checkout. Its `LICENSE` contains GPLv3;
the probe retains the original license beside build-only extracted sources.
The [machine record](2026-10-23-crust-selected-blockers.json) contains identities,
commands, return codes and retained artifact/log hashes.

The required entry is the original `ecall_safe_store2` declaration
(`src/enclave/Enclave.edl:53`) and its original body (`Enclave.cpp:421–473`).
The host sequence under assessment is:

| Call | Type/key | total_size | partial_size | offset | Effect expected from source |
| --- | --- | --- | --- | --- | --- |
| 1 | `ECALL_RESTORE_FROM_UPGRADE`, K | `0x100` | `1` | `0` | Allocate/zero 256 bytes, save pointer in the global map, retain allocation |
| 2 | Same type/key | `0x1000` | `0x400` | `0x800` | Reuse that allocation and attempt a 1,024-byte copy 2,048 bytes from its base |

Both calls have `offset + partial_size < total_size`; neither executes restore
dispatch. This differs from DEMO-MATRIX's completing second call. The source is
an ordinary copied ECALL input, not a `[user_check]` pointer. Full storage worker,
HTTP/chain/IPFS deployment, C04/C06 sealing defects, spacex replication and
successful restore completion are outside this assessment.

## Fresh probes

Read the documentation index, design, integration guide, status, preset and
private-libc++ guidance. Rebuilt/checked the current pass and modified generator
and verified the prepared private-libc++ inputs. Used Clang 21.1.8, C++17,
frontend/codegen `-O2`, no exceptions/RTTI, and the full `all-compat-v1` preset.
The successful object manifests confirm protected globals and lifecycle enabled.

The diagnostic source split preserves the exact selected function body, pool
and mutex definitions, original dispatch initializer, and original `SafeLock`.
The dispatch initializer occupies a separate translation unit so its dependency
can be assessed independently. Minimal includes replace the unrelated umbrella
header; original `Parameter.h`, `CrustStatus.h` and `SafeLock.h` are consumed.
No restore or mutex stub, raw admission entry, service mapping or check exemption
was supplied. The inventory comes from freshly generated frontend definitions
of 26 configured library sources and the three diagnostic application units;
historical library objects are not reused or linked.

| Native probe | BASELINE | RADIX_ONLY | MAC27 |
| --- | --- | --- | --- |
| Selected original EDL declaration, 1 ECALL / 0 application OCALLs; generated C/ABI syntax | Passed | Passed | Passed |
| Selected original function, pool and mutex globals; object compilation | Passed | Passed, 314 checks | Passed, 314 checks |
| Original `SafeLock.cpp`; object compilation | Passed | Rejected: `sgx_thread_mutex_unlock` | Same rejection |
| Original dispatch initializer; object compilation | Passed, unresolved restore symbol retained | Rejected: `ecall_restore_from_upgrade` | Same rejection |

These are intentional admissions stops in an incomplete definition/service
closure. The checked selected IR routes allocation, zeroing and the hostile
copy through `encbound_malloc`, `encbound_memset` and `encbound_memcpy`; it
retains the supplied copy length. Object compilation is not final closure
acceptance. The two protected rejections exit the compiler with code 134;
they are not application crashes or observed prevention.

## What blocks the selected integration

1. **Exact mutex service, including state integrity.** `SafeLock.cpp:3–27`
   calls `sgx_thread_mutex_lock` and `sgx_thread_mutex_unlock`; neither has an
   application adapter in this closure. The first reported rejection is unlock;
   frontend IR confirms lock is also required. Serial calls do not require a
   threading-model change, but do not authorize deleting these calls.

   A whole-range check followed by passing the decoded application mutex to
   the SDK is insufficient as an adapter contract. The pinned `sgx_thread.h:48–55`
   stores owner and queue thread values in the object. In
   `sdk/tlibthread/sethread_mutex.cpp:74–125`, lock traverses the queue and may
   insert a thread; `sethread_internal.h:46–72` casts those values to private
   thread-data pointers, reads `m_next` and writes queue links. `CHECK_PARAMETER`
   only checks that the outer object lies inside the enclave. Application data
   corruption can alter these fields even when the object occupies a protected
   global slot. Range validation alone does not authorize the embedded pointers.

   The service needs an explicit bounded serial state/ownership contract that
   prevents untrusted queue/owner values from directing unchecked SDK accesses,
   or private mutex state with a checked association. Preserve SDK/runtime
   privacy and actual lock/unlock semantics. These are options to review and
   test, not implemented or proven-safe adapters. If SDK mutex code is retained,
   include any required pinned SDK-only event OCALL proxies in the final bridge;
   zero application OCALLs does not establish zero SDK dependencies.

2. **The retained callback address still needs a definition.** The original
   dispatch map (`Enclave.cpp:7–9`) is dynamically constructed with
   `ecall_restore_from_upgrade`. The fresh split initializer still rejects its
   omitted definition in both protected profiles; BASELINE's undefined-symbol
   listing independently retains it. Moving code into separate files or merely
   stopping before dispatch does not remove the dependency.

   For a faithful unchanged completion path, that wrapper (`:380–388`) reaches
   `Workload` and `id_restore_from_upgrade`; `Identity.cpp:1162` adds JSON,
   restored state and ECC verification. That closure is outside the selected
   prefix and was not compiled here. For a prefix-only workload, explicitly
   record how completion is excluded. An application-owned terminal completion
   fixture is a possible declared adaptation; it must not implement a fake
   successful restore, alter the earlier allocation/reuse/copy, or be reported
   as original restore support. No such adaptation was made in this assessment.

The selected EDL types, `std::map`, callbacks, mutable globals and global
constructors have existing routes; the fresh probes do not identify them as
new framework blockers. The original umbrella header's crypto/storage includes
are not demonstrated runtime requirements of this prefix. A complete private
library rebuild, placement and final ownership/startup/permission audits remain
normal integration work, not completed checks.

## Recommendation and remaining evidence

Treat this as **Moderate, conditional on a bounded mutex contract and an explicit
prefix-only completion adaptation**. Keeping real restore raises closure work
to the earlier High estimate. There is no evidence here that the prefix requires
threads, TLS, new pointer semantics, a new backend or a full worker deployment.
Any solution that actually changes a governing boundary or target must follow
the owner's decision rule; none was introduced by these probes.

Next implementation should close those two dependencies, rebuild the complete
application/library closure under the preset and establish normal incomplete
transfers with observed data/pool reuse. Use the same-key sequence above for
the hostile case and retain independent BASELINE observations. Exercise bounded
session/resource behavior; incomplete transfers retain buffers, so normal
cleanup/completion and unbounded-session claims cannot be inferred.

Given a retained `0x100` slot and the emitted whole-range copy, `0x400` bytes
exceed the slot width. Both protected profiles are expected to reject with
RANGE, if the call reaches that check. This is a design/IR prediction, not a
MAC27-specific demonstration or an observed result. Smaller copies after a
cross-slot jump need separate RADIX_ONLY/MAC27 reasoning.

No application link, final ownership audit, native application execution,
SDK SIM, SGX hardware, attributed protection or performance run was performed.
BASELINE corruption and the proposed protected rejection remain unestablished.

Reproduce the assessment with the existing pinned SDK, prepared private headers
and source checkouts:

```sh
python3 evidence/repros/2026-10-23-crust-selected-probe.py
```

Outputs are under `build/crust-selected-assessment-2026-10-23/`; the probe builds
only tooling, selected bridges, frontend inventories and diagnostic objects.
