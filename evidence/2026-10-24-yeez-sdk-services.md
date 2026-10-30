# YeeZ checked SDK DH/crypto integration — 2026-10-24

The owner requested implementing the remaining checked SDK calls. The nine
services are implemented in [apps/yeez](../apps/yeez/README.md), with unchanged
SDK algorithms and unchanged original YeeZ/EDL bodies. The selected original
dependency units now compile and place in all three profiles, including DH,
secp256k1, GCM and ECDH. Six alternative raw/sealed relocatable application
links resolve their application symbols. Full original YeeZ enclave linking and
analyzer execution remain unestablished.

The real SDK service fixture passes four SDK simulation configurations and
180 ECALLs. Native spy contracts, compiler admission and dependency-only builds
remain separate evidence classes. Commands, retained source/IR/object/image
hashes and results are in [the JSON record](2026-10-24-yeez-sdk-services.json).

## Implementation and ownership

The application-only header redirects SDK RNG, GCM encrypt/decrypt, CMAC,
SHA-256, secure memset, DH initialization and LAv1 initiator message 1/message 3
calls to `yeez_*` declarations. Exact protected admission mappings route these
to trusted `encbound_yeez_*` definitions. BASELINE uses the same adapter contracts
with ordinary application pointers. SDK/runtime/bridge compilation omits the
redirect header. No global compiler allowlist, disabled check, SDK data
reclassification or raw SDK application admission is introduced.

The RNG/GCM/CMAC/secure-memory checks follow the existing SGX-KMS patterns.
Every SDK-accessed input/output extent is validated before dispatch; statuses
pass through unchanged. Zero-length conventions retain optional pointer
presence without authorizing pointee access. SHA-256 checks its complete input
and 32-byte output; fixed-size keys, IV and tags retain their exact extents.
The SGX-KMS adapter source is unchanged and its four native regression rows
still pass 22 pre-service rejection cases each.

The reviewed pinned SDK session layout contains scalar/key data, no pointers or
SDK heap handles. The public 200-byte caller-owned state stays application data.
DH uses private SDK-resident staging and copies back SDK session/output writes
on both success and failure. Session and preserved output buffers require
read/write access. Sensitive private session/key staging is cleared before
release. SDK state-machine and cryptographic behavior remain original.

Message 3 snapshots its fixed header and validates the entire overflow-safe
declared tail. Private staging restores the validated length after copying, so
a host race cannot enlarge the SDK read. A test allocator mutates the outside
header between validation/copy and demonstrates this bound. Staging exhaustion
returns out-of-memory before SDK dispatch with caller state unchanged. Overflow
and overlapping DH objects reject as invalid parameters before dispatch; the
selected original callers use disjoint objects. The adapter README states
these preflight contracts rather than claiming every rejected-input state write
equals a direct SDK call.

## Fresh validation

| Evidence class | Result |
| --- | --- |
| Native real checker/allocator, recording SDK spies | Four O0/O2 × RADIX_ONLY/MAC27 rows; 116 total pre-service range/policy/tag rejections |
| Native staging/error controls | Private input/output staging, copied-back SDK error writes/status, nullable SDK arguments, alias rejection, oversized tail/overflow, allocation failure and changing outside-header length pass |
| Compiler admission | 54 cases: nine services × two protected profiles × valid redirect/raw call/missing mapping; only configured redirects accept |
| Real SDK SIM fixture | BASELINE, RADIX_ONLY and MAC27 at `0x40000000`, plus MAC27 at `0x140000000`; 45 calls each, 180 total |
| Known answers and recovery | 36 SHA/CMAC/AES-GCM vector groups, RNG/secure clearing, bad GCM tag rejection and recovery |
| Real SDK DH | 108 successful key agreements, 36 rejected tampered message-3 calls and subsequent reinitialization/recovery; zero/eight-byte additional properties and SDK parameter/state errors |
| SDK SIM debugger attribution | 14 range/tag controls attributed to `encbound_require` in SHA, GCM and DH adapters, before the selected bad access |
| Original dependency compilation/placement | 33 BASELINE and 34 objects per protected profile; zero remaining selected-unit compiler failures |
| Dependency archives and relocatable links | HPDA/stbox/crypto/fflib archives per profile; six raw/sealed application variants resolve application symbols and retain only named runtime/adapter/OCALL references |

The simulation fixture links the unchanged pinned SDK and uses a trusted
test-only responder. It compares AEKs without exposing the responder's private
key or address. Cryptographic constants have separate known-answer oracles.
Pinned SDK DH converts a message-3 MAC verification failure to
`SGX_ERROR_UNEXPECTED`; the fixture follows that actual source behavior. GCM
retains its own `SGX_ERROR_MAC_MISMATCH`. No stubbed DH success is used.

All four images pass application/trusted ownership, SDK archive identities,
ELF/loaded-page permissions, signing metadata and signed-image audits. Every
application object uses the integration preset. Native tests use spies and a
synthetic platform; they do not supply SGX or cryptographic evidence. Debugger
traces identify the enforcing adapter/check/category; a signal alone is not
counted as protection. This is a service-fixture result, not a YeeZ C13/C14
vulnerability result.

## Selected YeeZ build

`apps/yeez/build_dependencies.py` consumes the recovered pinned October 24
source/RTTI/formatter inputs and inventories actual frontend definitions after
applying the service header. It uses the full integration/EH/private-libc++
configuration throughout. The secp256k1 C source retains the matched scalar
frontend configuration and explicit private formatter redirect established by
the prior dependency work. Original source and EDL bodies stay unchanged.

The retained successful build is `build/yeez/checked-dependencies-attempt-1/`.
Previously blocked original `dh_session.cpp`, `dh_session_initiator.cpp`,
`secp256k1.cpp`, `rijndael128GCM.cpp` and `secp256k1_ecdh_sgx128.cpp` now compile
and place in both protected profiles. Checked IR has no remaining direct call
to the selected raw SDK/secure-memory functions. The actual adapter definitions
are bound separately in the SDK fixture.

The verifier checks the full source → input/checked IR → object → placement
identity chain and links raw/sealed alternatives separately because their
diagnostic callers share the same `probe` symbol. It links the common errno
provider once, then requires every unresolved application reference to be
satisfied; the remaining trusted runtime, SDK and generated OCALL names are
listed explicitly in the record. Relocatable output still lacks final enclave
layout, startup and bridge/runtime linkage and is not relabeled as an enclave.

Early fixture attempts exposed test-buffer sizing, archive-pin accounting and
loaded-page preconditions; none is counted as a passing row. The final fixture
keeps persistent application call state, the real SDK status oracle, complete
archive inventory and rebuilt final images. The production SDK algorithms and
application bodies were not changed to satisfy those checks.

## Reproduction and outstanding work

See [the working recipe](../apps/yeez/README.md). Reproduce native and admission
tests, the four SDK SIM rows and debugger controls, then use a fresh dependency
output directory and run `collect.py --dependencies <directory>`. The collector
rechecks object/image/manifest/log identities, archive members and all six
relocatable variants before writing this dated JSON.

The implemented checked service boundary is established for the selected APIs
and tests. The remaining integration is the original analyzer ECALL closure,
generated/trusted OCALL host services, real key-manager deployment/session,
original normal raw/sealed inputs/results, final original-enclave audits and
attributed C13/C14 controls. The service fixture is not substituted for those
workflows. Hardware, timing, general SDK/API coverage, LAv2, concurrency,
reentry, temporal safety and bugs in trusted SDK/adapters remain outside these
results. The pointer mechanism, protected scope, trust roles and backend are
unchanged.
