# Shared serial mutex support — 2026-10-23

The owner requested promoting the Crust stubs for reuse and marking mutex
support as correctly stubbed. Implemented the shared application component in
[apps/serial-mutex](../apps/serial-mutex/README.md) and updated the integration
support matrix and configuration guide. **Application SGX mutex lock/unlock is
correctly stubbed for explicitly selected serial/nonreentrant workloads.**

## Implementation and contract

`app_serial_mutex_lock/unlock` replace the Crust-specific names. Both functions
return success and perform no pointee access. They are compiled as application
code with the full preset and actual-definition inventory in every profile.
The generic redirect includes SDK declarations first and changes only the two
selected application call names. It is explicitly force-included for selected
application units; there is no global SDK symbol replacement or default-preset
change. Old Crust include/source paths forward to the single shared
implementation for compatibility; its current runner uses shared paths directly.

Each consumer must enforce serial entry across all its application entries,
including rejection of overlapping and nested invocation, and record omitted
synchronization. Lock ownership/error/contended semantics, condition variables,
trylock/timed locking, pthread mutexes and full `std::mutex` source closure are
outside this two-call contract. SDK/runtime mutexes retain their original
implementations and must not consume the redirect. The pointer mechanism,
protected scope, trusted boundary, backend and evaluation targets are unchanged.

## Fresh validation

Ran `python3 apps/crust-selected/check_serial_mutex.py` after promotion, using
the pinned original Crust `SafeLock.cpp`/header and GPLv3 license identity from
its existing recipe. Outputs use the new isolated path
`build/crust-selected/shared-serial-mutex-v1/all-compat-v1/`.

BASELINE, RADIX_ONLY and MAC27 each compile and place the shared source and
redirected original `SafeLock` under the complete preset. Each native row passes
64 gated sequences and 64 nested-entry refusals: **192 sequences and 192 refusals
total**. Protected rows use the real checking runtime on the existing synthetic
platform and an actual heap capability for the out-of-line `SafeLock` methods.

Direct stub calls with poisoned mutex fields, NULL, a PROT_NONE page and a
noncanonical encoding return success without changing live mutex bytes. Native
symbol checks and trusted test-only SDK-shaped spies confirm that raw SDK names
remain separate. The unredirected BASELINE control must exit **42** after
observing escaped SDK-shaped calls; it does. No test spy is an SDK mutex
implementation or an enclave link input.

All **48 recorded commands** have the expected return codes. Verified the
machine record's 137 retained artifact hashes, 32 source-input hashes and tool
identities. See [the machine record](2026-10-23-shared-serial-mutex.json) for
commands, logs, manifests, placed-object ownership, binaries and inputs.
The earlier [Crust-only result](2026-10-23-crust-serial-mutex.md) retains its
original configuration and outputs.

No additional application is claimed integrated. Each consumer needs its own
entry-policy and selected-workload evidence. Crust restore dispatch and its
complete enclave closure remain open. No new Crust SDK SIM, hardware, final
enclave audit, spatial-protection or performance result is established here.
