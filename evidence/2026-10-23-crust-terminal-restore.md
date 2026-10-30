# Crust selected-path terminal restore adaptation — 2026-10-23

Implemented the owner's instruction to solve the remaining selected Crust
integration blocker by stubbing/removing restore. The application now supplies
a terminal `ecall_restore_from_upgrade` callback while preserving the original
dispatch initializer. Together with the earlier serial mutex adaptation, this
closes both identified application admission stops for C01's incomplete-transfer
scope. It does not complete the enclave integration.

## Adaptation and provenance

[restore_stub.cpp](../apps/crust-selected/restore_stub.cpp) has the original
callback signature and calls `abort()` without inspecting the buffer or size.
The full application preset routes it to the existing `encbound_cxx_fail`
terminal service in BASELINE, RADIX_ONLY and MAC27. The stub is application code
compiled through the driver, with its actual definition in the admission
inventory and its placed object in the selected application link. No raw SDK
service name, service mapping or check exemption is added.

The callback never returns, mutates restore state or reports successful restore.
It must not be linked alongside the original real restore wrapper. Workload,
identity restoration, JSON and ECC verification are deliberately excluded from
this selected source closure. A completing transfer terminates before the
original cleanup after dispatch; no completion/recovery/cleanup claim follows.
The pointer mechanism, protected scope, trusted-code roles and backend are
unchanged.

The runner extracts the exact original `ecall_safe_store2` body, buffer-pool
globals and dispatch initializer from `crustio/crust-sworker` revision
`a109e0a60a4ea256d884fde192b06b025e8bd6b1`. Minimal includes replace the unrelated
umbrella header, and the dispatch map remains in its separate translation unit.
The selected body SHA-256 is
`235991fbafed98c157c6b43c47707aac01149ce796b01b467821d6105c1c7603`, unchanged
from the [earlier assessment](2026-10-23-crust-selected-blockers.md).
Allocation, buffer retention/reuse and the supplied copy length are unchanged.
The original map still contains `{ECALL_RESTORE_FROM_UPGRADE, ecall_restore_from_upgrade}`.

The [expanded pins](../apps/crust-selected/pins.json) cover the original enclave
source/EDL, consumed `Parameter.h`/`CrustStatus.h`, `SafeLock` source/header and
GPLv3 LICENSE. Every file is checked against `git show` before extraction, and
the original license accompanies the extracted build sources. The terminal
stub/header, runner and native driver are new local code.

## Fresh checks

```sh
python3 apps/crust-selected/check_restore_stub.py
python3 apps/crust-selected/check_serial_mutex.py
```

The restore runner uses Clang 21.1.8, C++17, frontend/codegen O2 and the complete
`all-compat-v1` preset. It verifies prepared private-libc++ source/header pins and
freshly collects actual frontend definitions from the 26 configured library
sources and five selected application units. Historical library objects are
not linked or presented as fresh protected-library results.

| Check | BASELINE | RADIX_ONLY | MAC27 |
| --- | --- | --- | --- |
| Original selected body, pool and mutex globals | Compiles/places | Compiles/places, 314 checks | Compiles/places, 314 checks |
| Original dispatch initializer with terminal callback definition | Compiles/places | Compiles/places | Compiles/places |
| Original `SafeLock` with scoped redirect, shared mutex source and restore stub | All compile/place | All compile/place | All compile/place |
| Relocatable link of five application objects | Callback defined | Callback defined | Callback defined |
| Native terminal callback: NULL, PROT_NONE, noncanonical pointer | 3 SIGABRT | 3 SIGABRT | 3 SIGABRT |
| Omit callback definition from admission | Not a protected admission test | Dispatch rejects, exit 134 | Dispatch rejects, exit 134 |

All fifteen application objects compile/place with matching preset manifests.
The three relocatable links define the callback and contain no references to
raw SDK mutex calls, `Workload` or `id_restore_from_upgrade`. They still have
unresolved library/runtime references: partial linking is not a final closure
or ownership audit. Both protected selected bodies keep their allocation,
zeroing and copy adapters; the original `partial_size` argument reaches
`encbound_memcpy` unchanged.

The checked stub IR contains only the terminal adapter call followed by
`unreachable`, with no memory loads/stores or return. Each native driver calls
the separately compiled/placed stub through a volatile function pointer. The
three arguments are NULL with zero size, a PROT_NONE page with its page size,
and `0x5000000000000001` with `SIZE_MAX`. All nine processes exit via SIGABRT
using the actual terminal service. No pointer validation or spatial protection
result is inferred from this non-access/termination check. The driver is trusted
test code and does not run the original transfer body or initialize an enclave.

The two missing-definition controls reproduce the original diagnostic,
`unsupported external function reference: ecall_restore_from_upgrade`, before
producing an object. These are deliberate compiler admission failures, separate
from the nine application-stub terminations. The shared mutex regression also
passes all three native rows: 192 gated sequences and 192 nested-entry refusals
in total, plus the expected unredirected-call control.

The [machine record](2026-10-23-crust-terminal-restore.json) retains commands,
expected/actual return codes, logs, source/tool inputs, manifests, ownership
records and artifact hashes, plus the mutex regression identity. Restore
outputs are isolated under
`build/crust-selected/terminal-restore-v1/all-compat-v1/`; the earlier assessment
and mutex evidence retain their original configurations and results.

## Remaining integration work

Rebuild the complete selected private-library closure under the same preset;
link and audit the final enclave's application/SDK ownership, startup and page
permissions; enforce serial/nonreentrant entry across every selected ECALL; and
execute normal incomplete transfers with observed pool/data reuse. Native
callback execution and object compilation do not establish those steps.

No whole selected Crust native execution, SDK SIM, SGX hardware, completed
restore, attributed C01 prevention, resource/cleanup or performance result was
established here. C02 spacex-storage requires separate pinned-source work.
