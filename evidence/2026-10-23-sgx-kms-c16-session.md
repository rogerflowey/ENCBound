# SGX-KMS enclave integration and benign C16 session — 2026-10-23

**Completed through the benign C16 fixture.** The original SGX-KMS enclave
application now builds, links, audits, signs and executes in SDK 2.26 SIM in
BASELINE, RADIX_ONLY, MAC27 and high-base MAC27. All four configurations reach
unchanged `ecall_proc_ma` with a valid fresh RA/GCM prefix and independently
verified outgoing ciphertext. Hostile protected/trusted target tests remain
unperformed; this is no C16 protection result.

This continues the [SDK-entry implementation](2026-10-23-c16-trusted-imports.md)
after the owner requested continuation through the application integration,
checked service closure, benign workloads and current-session C16 fixture.
The [recipe](../apps/sgx-kms/README.md),
[provenance](../apps/sgx-kms/PROVENANCE.md) and
[machine record](2026-10-23-sgx-kms-c16-session.json) supply reproduction and
identities. Earlier diagnostic/boundary-fixture records retain their historical
scope and results.

## Application and trusted closure

Upstream is `cloud-security-research/sgx-kms` at
`1c9d2d2df117845166196a1c3f6f2fb1b998e2c9`. All 67 cached files match the
existing source manifest. The runner copies the original enclave sources into
its build tree and records one explicit SDK compatibility port: unsupported
`b_pse != 0` returns `SGX_ERROR_FEATURE_NOT_SUPPORTED`; non-PSE uses ordinary
`sgx_ra_init`. It removes obsolete PSE-session calls from that configured body
and rejects custom key derivation at compile time. No successful PSE stub or RA
state/key stub is supplied. The full `ecall_proc_ma` source suffix remains
byte-identical and is separately hashed.

All four original application units (`isv_enclave.cpp`, `barbie_common.cpp`,
`barbie_server.cpp`, `seal.cpp`) and the 12-object selected
formatter/helper/common-errno closure are compiled with the complete
`all-compat-v1` preset. Profiles use matched scalar frontend/codegen O2, no
exceptions/RTTI, protected writable globals in the protected configurations,
and reuse/proofs/fast paths off. Every object retains source/header identities,
input/checked IR and the compilation-to-placement hash chain. No application
unit is trusted or exempted. The selected formatter retains its existing
serial/long-double exclusions and source/license pins.

The EDL wrapper imports every unchanged original application declaration and
adds only pinned SDK-owned tstdc OCALLs needed by SDK/runtime code. Each image
exports 20 application ECALLs and the three SDK RA ECALLs; the application print
OCALL remains checked. All four generated BASELINE C/header files match the
installed stock Intel generator byte-for-byte. The SDK RA provider/state and
ordinary-transport/shared-gate contract are unchanged from the preceding work.

Fifteen exact application-only service aliases route to trusted adapters for
RA init/key/close, report creation, RNG, CMAC/GCM, sealing/unsealing/size/header
accessors, secure clearing and constant-time equality. Application printf and
vsnprintf use actual instrumented bodies; SDK libc remains separate. Complete
ranges are validated before SDK side effects. Init, key retrieval and report
creation use private staging and copy only successful initialized output.
RA contexts remain opaque scalars and returned session keys are the original
application's declared data, distinct from the private pointer-authentication
key. Raw SDK state/aliases do not escape. Unseal checks the header and full
claimed input plus output and in/out length cells; overflow rejects. Empty
GCM/CMAC pointer presence uses private dummy bytes without permitting a
zero-length application access. SDK/runtime/bridge code is compiled separately
with ordinary headers.

Both unsigned and final signed images pass object/definition/closure checks,
application-global ownership and RO/RELRO/RW/BSS permissions, exact SDK archive
pins, SDK RA provider/member/state checks and signing metadata. Trusted
compilation dependencies and object hashes are retained. The host checks actual
loaded code/data permissions and the requested enclave base. No mechanism,
protected scope, threat model, trusted-domain role, backend or target change was
required; no installed SDK or sibling-source tree was modified.

## Executed checks

| SDK SIM configuration | Fresh message-2 exchanges | ECALLs | Successful C16 calls | Independent output checks |
| --- | ---: | ---: | ---: | ---: |
| BASELINE, `0x40000000` | 3 | 103 | 6 | 27 |
| RADIX_ONLY, `0x40000000` | 3 | 103 | 6 | 27 |
| MAC27, `0x40000000` | 3 | 103 | 6 | 27 |
| MAC27, `0x140000000` | 3 | 103 | 6 | 27 |

The independently implemented OpenSSL peer derives session keys from ECDH/CMAC,
signs `gb || ga` and supplies a valid message-2 MAC. The SDK's actual RA code
processes those messages. Each row checks the report hash/padding, early key
retrieval, bad signature, bad message-2 MAC, unsupported PSE and closed-context
errors. CMAC uses the independently derived MK. No SDK database reset or
key injection is used.

Benign public-ECALL workflows cover sealed RA-key retrieval, sealed-length
accessors, known-key encryption/decryption with empty or three-byte AAD, bad-tag
handling, random key generation/comparison, secret transport, KEK provisioning,
equal-length store/get, project-ID recovery and successful client-secret
sealing. OpenSSL checks known plaintexts against independently derived/recovered
keys. Inputs are 16 or 37 bytes, with 16-byte application keys; selected
functional behavior is established, not all parameter combinations or resource
limits. The exported `server_put_secret_data` helper is exercised through C16,
not substituted for that public entry.

For C16, `*c_p_net_ctxt` names a real host-side structure with the exact upstream
layout and a known host key. Message 4 carries a valid 16-byte current-session
GCM payload under the independently derived SK. Full-size zero-initialized
`sealed_mk`/`mk_sk` buffers and matching caller-provided identity fields select
the original new-key branch. The host verifies the returned nonce with its
known key, authenticates the returned server-key ciphertext and cross-checks
that key against `mk_sk` decrypted with the returned sealed master key. A
second successful C16 call verifies reuse within the same session. This is
repeated for three fresh RA sessions per image, not a stale transcript replay.

Each image also runs three C16 identity mismatches (return 3) and three invalid
GCM tags (return 4), followed by success in the same session. The bad-tag row
stays at the 16-byte C16 payload size; it is not a C17 overflow experiment.
Ordinary application error messages appear in those passing control logs.

Four separate **native** rows run RADIX_ONLY/MAC27 at O0/O2 over the real runtime
and fake platform, using SDK recording spies. Each verifies 22 range/policy
rejections before SDK side effects (88 total), including complete output cells,
keys, report, GCM input/output/IV/AAD/tag, CMAC, sealing/unsealing, secure clearing
and equality spans. They also test init/key/report failure-output staging,
ordinary status propagation, zero-length crypto arguments, empty AAD and trusted
memory refusal. Each row records 14 SDK spy service invocations. These are
adapter-contract tests, not native SGX-KMS cryptographic or isolation results.

## Reproduction and remaining work

```sh
python3 apps/sgx-kms/test_adapters.py
python3 apps/sgx-kms/run.py --build build/sgx-kms/session-c16-2026-10-23
```

Fresh logs, manifests, prepared sources and final signed images are retained in
`build/sgx-kms/session-c16-2026-10-23`; native adapter outputs are under
`build/sgx-kms/adapter-native`. No shared compiler/runtime/generator change was
needed, so validation is the complete fresh application matrix, native adapter
suite, source/closure/pin/permission/signing checks and focused syntax/link checks.

The next C16 experiment must keep this valid prefix and compare a benign host
key with raw protected-application and trusted key targets, recording baseline
consumption and the exact enforcing check in each protected profile. No such
hostile-pointer experiment has been executed or attributed here.

Full original-host message-3/quote/IAS orchestration, PSE, hardware attestation,
Barbican deployment and performance remain separate. SDK SIM supplies no SGX
hardware isolation. The selected C16 branch compares identities but does not
verify their quote signatures; no attestation result is inferred from those
fields. Original application error paths retain leaks and upstream defects;
cleanup, exhaustion, all public-API input combinations and C17–C19 protection
remain unestablished. This work completes the authorized benign session stage,
not full service deployment or the next protection stage.
