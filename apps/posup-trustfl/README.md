# POSUP and TrustFL required ECALL integrations

Both selected workflows pass **BASELINE, RADIX_ONLY, MAC27 and high-base MAC27
in Intel SDK 2.26 simulation**. Required upstream bodies and public signatures
are preserved. No core compiler/runtime mechanism changed.

| Application and pin | Selected original ECALLs | Per configuration |
| --- | --- | --- |
| `thanghoang/POSUP@9a6e181763535fd927bca1749cd804e5d77f2f73` | `ecall_getPathID`, `ecall_setFileIDs` | 54 calls; 234 integer comparisons |
| `zeyu-zh/TrustFL@9e05a7e160bbf4fa1e7a426767f69158ea89b22d` | `ecall_init`, `ecall_data_preprocess` | 5 calls; 5,820,000 byte/record comparisons; four complete 60,000-record preprocessing calls |

POSUP adds a test observation ECALL, `diagnostic_fileids`, using an ordinary
copied output buffer. It exposes only the selected application-owned set.
Its 18 calls per configuration are included in the 54-call count.

Run from the restart root with Clang/LLVM 21, the pinned SDK/source installation,
OpenSSL, Python and the read-only screening Git checkouts available:

```sh
python3 apps/posup-trustfl/run.py --app POSUP
python3 apps/posup-trustfl/run.py --app TrustFL
python3 apps/posup-trustfl/confused_deputy.py --trace
python3 apps/posup-trustfl/closure_probe.py
python3 apps/posup-trustfl/controls.py
python3 apps/posup-trustfl/verify.py
```

`confused_deputy.py` reuses the saved `all-compat-v1-final` rows and compiles one
extra host per row; it does not rebuild an enclave. `--trace` adds the protected
debugger attribution, and `--evidence <file>` writes the machine record.

`record.py --record build/evidence/<fresh-name>.json` verifies the saved matrix before
writing an append-only machine record; the dated report uses the recorded final
matrix, not any earlier setup attempt.

Outputs default to `build/posup-trustfl/all-compat-v1-final/`. Builds and native
followups require fresh destinations and preserve previous evidence. To rerun,
pass the same fresh `--out build/<new-name>` to each command. `run.py --skip-build`
checks a saved functional log and reruns its audit; it does not execute the host.
Each single-row `build.py` invocation also accepts `--source` for the pinned
Git checkout and `--base`; see its help. The source default is
`build/paper-sources/{POSUP,TrustFL}`. No files in
those checkouts are changed. Source is extracted from the exact Git revisions,
never from their mutable working trees or prebuilt objects.

Every row builds its own current pass and generator, uses frontend/codegen O2
and the complete `config/integration.env` preset, retains IR/manifests and signs
a one-TCS enclave. The high-base row uses `0x140000000`; other rows use
`0x40000000`. The signer-derived enclosing extent is 64 MiB in the recorded run.

POSUP retains the exact two required bodies, their `int` typedef and three
needed globals. The set uses the existing private instrumented libc++ build
(26 objects); `abs` uses one pinned BSD SDK C unit, renamed `app_posup_abs` and
compiled as application code. Together with the selected C++ unit, each row has
28 application objects. Inputs cover empty/reset, singleton, signed values,
duplicates, zero, `INT_MAX`, and twelve elements over three sequential rounds.
Every observed sorted set matches a host `abs`/sort/dedup oracle. `INT_MIN`,
for which upstream `abs` has undefined behavior, is excluded. `pathID` remains
its original zero initialization: no ORAM operation is selected to change it.

TrustFL retains the entire 60,000-record loop, 28x28 image size, 128-byte key,
input-header offsets, ignored scalar lengths, allocation and lack of free.
There is one application object and no selected STL dependency. Protected rows
reuse the exact checked RNG/HMAC contracts from `apps/go-consensus-usig/adapters.c`.
SDK key/crypto implementation state stays private; the application key belongs
to a protected global. The pre-init diagnostic uses the upstream zero-initialized
key and compares all 1,920,000 output bytes with independent OpenSSL HMACs.
After the original `ecall_init`, repeated messages must have equal HMACs,
repeated calls must agree, and changing one label must change exactly that
record's HMAC. The generated random key is never exported; initialized-key
checks establish those relations rather than an independent known-key oracle.
One call passes zero scalar lengths with complete backing arrays to establish
the original ignored-length behavior without an out-of-bounds access.

`audit.py` checks extraction/source pins, compiler inputs, preset/profile,
IR/placement/object identities, actual definition ownership, private-library
archive bytes, known services, exact linked objects, bridge inputs/outputs,
SDK archives, ELF ownership/permissions, signed-versus-linked bytes, bootstrap
ordering and signed base/extent. BASELINE bridge bytes equal stock Intel output.
The host checks loaded application page permissions. Eight corruption controls
reject altered bodies, objects, protected-global settings and ECALL inventories;
each restores exact original bytes before final verification.

## Direct `[user_check]` pointer-forgery control

`confused_deputy_host.c` keeps the original declarations and bodies and names
enclave-internal addresses for the selected ECALLs. It is separate from the
functional host and the integration evidence.

- POSUP `cd-read` makes `ecall_setFileIDs` read two stable `.data` words from the
  image (returned by the test-only observation ECALL); `cd-write` makes
  `ecall_getPathID` store `pathID` over the first word.
- TrustFL `cd-read` takes all 60,000 label bytes from image `.text`;
  `cd-write` writes the 60,000 HMACs (1,920,000 bytes) into a mapped span inside
  the enclave extent; `cd-read-data` makes the training-data loop read image
  `.text` until it faults at the mapped-image boundary.

BASELINE performs the accesses. RADIX_ONLY, MAC27 and high-base MAC27 terminate
with SIGILL (`encbound_abort (code=3)`, `ENCBOUND_ERR_POLICY`) at the first raw
enclave address: POSUP `prepared/Enclave.cpp:19` (`encbound_memcpy`) and `:10`
(`encbound_require`); TrustFL `:41`, `:45` and `:40`. Every `control` run uses
host buffers and passes in all four rows, and the functional hosts are unchanged.
The saved rows are required; no enclave is rebuilt. See
[the evidence](../../evidence/2026-10-23-posup-trustfl-user-check.md).

The required subsets have no remaining observed integration blocker. Broader
application work remains:

- **POSUP:** original `conf.h` includes removed `sgx_tae_service.h`. A separate
  full-unit probe removes that unused include and the C-only `bool` macro;
  the original full EDL then generates. `BlockSGX.cpp` compiles in both
  protected profiles. The original oblivious primitives explicitly reject
  inline assembly, including memory-accessing copy/set routines. The wider
  unit also needs selected `ceil`/`log2` libraries, AES-CTR/CMAC service closure,
  ORAM state, host services and workflow oracles. Existing math and checked
  AES-CTR routes are available; their absence from this full port is incomplete
  integration work. Assembly is a confirmed unsupported construct. It was not
  bypassed or moved into trusted code.
- **TrustFL:** original full EDL generates, and unchanged `verify.cpp` reaches
  frontend IR with private libc++ headers. Its parameter-processing path uses
  streaming SHA-256 contexts and `std::to_string(int)` outside the selected
  library configuration. A native followup builds the actual-caller libc++
  closure and identifies the remaining conversion call after diagnostic mapping
  to existing checked SHA adapters. The mix-network recipe already demonstrates
  a local decimal conversion port; a full SHA port must match the length ABI
  and close the upstream leaked contexts. MiniDnn/Eigen, model loading/training,
  original host and the remaining ECALLs are unported and unexecuted. These
  probes do not establish an intrinsic ENCBound mechanism blocker for TrustFL.

The selected preprocessing function ignores its lengths, does not check malloc
failure, and leaks 785 requested bytes per call (a 1,024-byte protected slot).
Those source behaviors are retained; unlimited repetition or resource exhaustion
is not established. All original `user_check` arrays and integer-encoded output
pointers remain host memory in this functional harness. No malformed-pointer
rejection, pointer-forgery prevention, exact object bounds, full application,
hardware, performance or automatic teardown result is claimed.

See [the evidence and blockers](../../evidence/2026-10-23-posup-trustfl.md) and
[origin/license record](PROVENANCE.md). Earlier build-setup attempts under
`all-compat-v1` and `all-compat-v1-v2` are diagnostics, separate from the final
eight-row matrix.
