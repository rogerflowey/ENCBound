# POSUP and TrustFL required ECALL integrations — 2026-10-23

**Both requested required-ECALL subsets run in all four matched SDK SIM
configurations.** No nontrivial compiler/runtime mechanism change was needed.
The complete upstream applications remain outside this bounded result.

| Application | Pinned revision | Required entries |
| --- | --- | --- |
| thanghoang/POSUP | `9a6e181763535fd927bca1749cd804e5d77f2f73` | `ecall_getPathID`, `ecall_setFileIDs` |
| zeyu-zh/TrustFL | `9e05a7e160bbf4fa1e7a426767f69158ea89b22d` | `ecall_data_preprocess` |

The owner permitted choosing the rest of each workload. The recipes therefore
select the exact required bodies and their dependencies, preserve public
signatures and `user_check`, and record the omitted application operations.
POSUP includes a test-only copied-output ECALL for observing set contents;
TrustFL includes the original `ecall_init`. Source is read from exact Git
objects in the read-only screening checkouts. The
[provenance](../apps/posup-trustfl/PROVENANCE.md) records origin/licenses.

## Configuration and results

Each row uses the entire all-compat-v1 preset, including protected writable
globals, frontend and backend O2, reuse/proofs/fast paths off, no C++ EH, one
TCS, a 1 MiB SDK stack, 2 MiB trusted SDK heap, 16 MiB protected arena and
32 MiB reserved memory. The signer derives a 64 MiB image extent. Each builds
an isolated current pass and native generator; compiler/bridge inputs are
hash-bound to the produced artifacts.

| Profile | Base | POSUP | TrustFL |
| --- | --- | --- | --- |
| BASELINE | `0x40000000` | PASS: 54 calls / 234 comparisons | PASS: 5 calls / 5,820,000 comparisons |
| RADIX_ONLY | `0x40000000` | PASS: 54 / 234 | PASS: 5 / 5,820,000 |
| MAC27 | `0x40000000` | PASS: 54 / 234 | PASS: 5 / 5,820,000 |
| MAC27 | `0x140000000` | PASS: 54 / 234 | PASS: 5 / 5,820,000 |

Totals are **216 POSUP ECALLs / 936 integer comparisons** and **20 TrustFL
ECALLs / 23,280,000 byte-or-record comparisons**. Each TrustFL row executes
the full original 60,000-record preprocessing loop four times; its fifth call
is initialization. No training-size reduction is used.

POSUP retains its real `std::set<int>` state and iterator. Twenty-six configured
private libc++ objects, one pinned SDK `abs.c` compiled as private application
code and one selected C++ unit form the 28-object application closure. Its
three rounds exercise empty/reset, singleton, signed/duplicate/zero values,
`INT_MAX` and twelve elements. Host sort/dedup checks every copied output
element and canaries. The path-ID ECALL stores the original zero-initialized
global; ORAM operations that assign a new path are not selected.

TrustFL is one instrumented C++ application unit, retaining the original key,
metadata and output-pointer globals. Checked RNG/HMAC services reuse unchanged
USIG adapter contracts and call the actual pinned SDK. The pre-init zero-key
diagnostic compares all 1,920,000 HMAC bytes with independent OpenSSL results.
After initialization, equal records produce equal HMACs, repeated calls agree,
and one changed label alters exactly one record. The random key stays inside
the enclave, so those initialized-key checks are relational oracles. Complete
host backing arrays with zero scalar lengths exercise the function's original
ignored-length behavior. Input offsets, 128-byte key, 28x28 dimensions,
60,000 records and allocation/lifetime behavior are unchanged.

## Verified closure and controls

Every row passes source/body extraction, complete preset/profile, compiler
input and retained IR, object placement, private library archive/member,
application/trusted/SDK definition ownership, known external services, actual
linked object list, exact SDK archives, bridge input/output, signed/linker
image identity, ELF permission/ownership and base/extent audits. Protected
bootstrap order passes. BASELINE generated C/headers equal stock Intel output.
The host independently verifies loaded application page permissions.

Eight corruption controls reject changed selected bodies, placed object bytes,
protected-global manifest settings and bridge ECALL inventories, for each
application. Exact original bytes are restored after every control. The final
saved-evidence verifier reruns all eight complete closure audits and validates
371 retained record/log hashes, saved outcomes, image identities and native
diagnostic records.
Compiler-driver and library manifests retain the actual source/ABI settings;
no raw SDK call is admitted by name alone.

## Blockers and remaining work

**No observed blocker remains for the selected required ECALL workflows.**
The larger application diagnostics identify different limitations:

| Scope | Observed evidence | Disposition |
| --- | --- | --- |
| POSUP original headers/EDL | `conf.h` includes missing SDK `sgx_tae_service.h`; original C++ unit has `#define bool _Bool`. | Separate diagnostic removes that unused include and C-only macro. The full original interface then generates and frontend compilation succeeds. These are SDK/compiler port issues, resolved for the selected subset. |
| POSUP oblivious primitives | Protected compilation explicitly rejects inline assembly in `ocmp_eq`; retained original IR also contains memory-accessing `o_memcpy_8`, byte copy and memset assembly. | Confirmed unsupported original construct. A full port needs instrumentable application implementations or separately authorized support. No check bypass/trusted reclassification was used. |
| POSUP full ORAM unit | Adding actual `BlockSGX.cpp` definitions and existing checked AES-CTR/RNG mappings reaches unresolved `ceil`; IR also uses `log2` and AES-CMAC. `BlockSGX.cpp` itself passes both protected profiles. | Existing selected-math and checked AES-CTR recipes can be connected; CMAC/full ORAM ownership, host services and functional oracles are unfinished. This is incomplete full-application closure, not a new `ceil` compatibility defect. |
| TrustFL original interface/unit | Full original EDL generates in every profile; unchanged `verify.cpp` reaches frontend IR with private libc++ headers. Initial raw streaming SHA-256 calls reject. | Existing TPDV checked SHA services provide a starting pattern. A native-only diagnostic maps these and rebuilds actual-caller libc++, then stops at private `std::to_string(int)`. |
| TrustFL full parameter/ML workflow | `std::to_string` is outside the configured libc++; parameter paths retain unclosed SHA handles. MiniDnn/Eigen/model loading/training and other ECALLs are unported/unexecuted. | The existing mix-network recipe demonstrates an application decimal-conversion port. SHA length ABI and context cleanup need reconciliation. No new mechanism blocker is established for TrustFL. |

Diagnostic mapping is compiler evidence only: no full-unit diagnostic object
or hypothetical adapter closure enters a selected enclave. Original sources,
modern-header port, selected sources and successful SDK SIM results remain
distinct. Earlier setup errors and the initial missing private `abs` definition
are retained under the earlier output trees and are not final blockers.

The selected TrustFL function ignores input lengths, does not check allocation
failure and leaks 785 requested bytes per call (one 1,024-byte protected slot).
The finite matrix preserves this source behavior. `INT_MIN` absolute value,
allocation exhaustion, unbounded sessions, varied ORAM paths, actual MNIST
datasets, full learning/ORAM functionality and automatic destruction are
unestablished. Source-only findings do not become dynamic protection results.

## Reproduction and evidence identity

Use the commands in [the application guide](../apps/posup-trustfl/README.md).
The recorded matrix and diagnostics live under
`build/posup-trustfl/all-compat-v1-final/`; each row retains `probe.json`,
`prepared.json`, `build.json`, `inventory.json`, logs, source, IR, isolated
toolchain, linked/signed images and host. The
[machine record](2026-10-23-posup-trustfl.json) binds their identities and lists
the exact required-body hashes and broader-source diagnostics.

All application execution is **SDK simulation**. All original-unit/primitive
probes are **native generation/compilation**. Original `user_check` arrays and
the integer-encoded TrustFL output pointer name host memory in this harness.
No malicious-pointer rejection, confused-deputy prevention, hardware isolation,
performance, general memory safety or complete upstream application result is
claimed. The pointer mechanism, protected scope, trust boundary and backend are
unchanged.
