# Pinned SDK RA ECALL boundary fixture

Run from the repository root:

```sh
python3 tests/integration/sdk_ecalls_test.py
python3 tests/sdk-ecalls/run.py
python3 evidence/repros/2026-10-23-c16-sdk-imports.py
```

The first command supplies twelve native O0/O2 mixed/SDK-only rows, admission
failures, EH exclusion, selective imports and stock BASELINE equality. Its SDK
bodies are transport spies over the native synthetic platform and real runtime.
They check raw SDK buffers, application capabilities, real shared-gate nested
refusal, terminal initialization failure, four allocation failures and six copy
failures per row, cleanup and recovery. Refused nested requests reside on the
modeled host. This is transport evidence, not SDK RA execution or SGX isolation.

The second command builds, places, audits, signs and loads real Intel SGX SDK
2.26 SIM enclaves in BASELINE, RADIX_ONLY, MAC27 and high-base MAC27. The
application translation unit uses the complete integration preset. EDL imports
the unchanged pinned SDK RA entries plus SDK tstdc OCALLs. `trusted.c` implements
only exact checked initialization/key/close fixture adapters: complete ranges
are checked before side effects, SDK inputs/outputs use private staging and
opaque context values remain scalars. Initialization selects non-PSE (`0`);
no obsolete PSE service is stubbed or emulated. The static application session
counter is instrumented/placed with the closure. SDK RA database state stays
private, outside all application sections.

An independent OpenSSL P-256 peer signs `gb || ga`, derives the SDK CMAC keys
from ECDH and constructs valid message 2. Each configuration executes three
fresh exchanges, checks report `SHA256(ga || gb || VK)` plus zero padding, and
compares all six SK/MK outputs with the peer. State/error controls cover early
key retrieval, repeated get-ga, bad signature, bad MAC and closed contexts.
Passing a raw enclave address as message-3 `p_msg3` gets the SDK's own
`SGX_ERROR_INVALID_PARAMETER`; it is not a bridge range-check result. There
are 46 ECALLs per configuration. ELF and loaded-page checks cover fixed base,
code/data permissions, protected writable-global placement and SDK ownership.
The final audit checks the signed image as well as the unsigned image.

Nine final-link audit controls reject missing/stale manifests, ownership overlap,
raw application entry calls, explicit trusted imposters, wrong SDK members,
changed archives, SDK functions outside their pinned member and SDK data symbols
inside application memory. ELF-symbol mutations are inspected, never executed.

The third command verifies the pinned original SGX-KMS source manifest and
generates its unchanged EDL in all profiles: 20 application and three SDK entries,
one application OCALL, all four BASELINE C/header outputs equal to stock Intel.
It leaves the earlier blocker-assessment tree unchanged.

Build/link/sign/loaded-page methods are reduced from this repository's
`tests/early-bootstrap` fixture; new fixture code is original ENCBound support.
The unmodified SDK EDL/archive remain under Intel BSD-3-Clause; exact identities
and provider member are in `tools/edger8r/sdk-ecalls.json`. The host uses the
installed OpenSSL library, without vendoring OpenSSL code. `SGX_SDK` and
`PINNED_SRC` may select paths but all pin checks still apply. Results and command
logs are under `build/integration/sdk-ecalls{,-sim}` and
`build/c16-sdk-imports-2026-10-23`.

This fixture is not the SGX-KMS application. Full SGX-KMS non-PSE porting,
checked sealing/crypto/formatter/service closure and a current-session C16
message-4/GCM test remain separate work. No complete message-3, quote, IAS,
deployment, hardware-attestation, timing or C16 protection claim is made.
