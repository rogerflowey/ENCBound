# SGX-repo first-ten integration campaign — 2026-10-21

The requested campaign attempted the ten shortlisted repositories in their
recorded order. **One new bounded integration, FedServing, runs successfully;
the existing wallet has fresh full-preset validation; eight candidates are
stopped with explicit reasons.** Stopping difficult candidates was authorized.
No entry was replaced by another application or silently reduced to a passing
EDL subset. No frozen experiment target or acceptance gate is changed.

## Selection and method

[candidates.json](../apps/first10/candidates.json) freezes repository names,
revisions and original EDL paths from the owner's
`../SGX-repo/screening/2026-10-21/build-shortlist.csv`; the original CSV hash is
`d08b861cfd6ca7fb669159968537f132cc258b24c5e8f0e38e4aafa1d0daecc2`.
The machine record retains the authoritative hash and complete pins. Existing
screening checkouts were read only. The absent sgx-reencrypt checkout was fetched
at `6f065914b4173c5c0d4ec1aeab1a15875adea035` into this restart's build directory.

Every original-interface attempt used the modified Intel generator with actual
record headers and exact SDK-only import metadata. Both admitted interfaces
were subsequently exercised in real SDK SIM enclaves. Other diagnostic subsets
remain native generator/frontend/compiler evidence only. Successful frontend
or compiler admission is not counted as an integration or protection result.

The complete `all-compat-v1` preset applies across each successful application
and its application-library closure, including protected writable globals,
lifecycle, VLA, callbacks, aggregate ABI, allocations, atomics, virtuals and
variadics. Check reuse/local proofs/fast paths remain off; C++ EH remains off.
Existing private-library, EDL, ownership and application recipes were consulted
before classifying stopping points.

## Ten dispositions

The [campaign guide](../apps/first10/README.md) gives detailed causes,
adaptations and commands. Full revisions, diagnostics, command lines and log
hashes are in [the JSON evidence](2026-10-21-first10-integrations.json).

| Rank | Candidate | Current disposition |
| ---: | --- | --- |
| 1 | SGX_SQLite | Pointer-valued `char*` OCALL results reject; errno propagation and SQLite/POSIX closure remain unported. |
| 2 | ShieldStore | Anonymous HotCall typedef admission rejects; removing that ECALL only for diagnosis next rejects `void* sbrk_o`. Pointer graphs, worker execution and allocator closure remain unresolved. |
| 3 | sgx-log | Original sample imports are unclassified and obsolete under SDK 2.26; a diagnostic subset still rejects reentrant OCALL mode. Actual source units have comparison/missing-declaration errors and an unfinished checked crypto/formatting closure. |
| 4 | sgx-reencrypt | Copied `[out] uint8_t **data` in `untrusted_fs_load` rejects. Existing `user_check` support is not the issue. |
| 5 | secure-analytics-sgx | Removing obsolete sample imports admits its own 2 ECALLs/4 OCALLs. All 15 inspected C++ units compile; protected closure rejects raw AES-GCM use and two `vector.reduce.add.v4i32` sites. No enclave execution. |
| 6 | sgx-wallet | Existing recipe passes three fresh SDK SIM configurations with full preset and frontend/backend O2; attributed overflow and optimized-copy checks pass in both protected rows. |
| 7 | sgx-fs | Application EDL imports are unclassified; original `try/catch` rejects in this no-EH configuration with private libc++ headers applied. Filesystem/sealing/FUSE closure remains unfinished. |
| 8 | sgx-netting | Intel parser rejects original `isptr` on `uint8_t **`. Removing just those attributes exposes `void* ocall_malloc` result rejection; pointer-output/crypto closure remains unresolved. |
| 9 | FedServing | New bounded L2 combiner passes four SDK SIM configurations, 24 numerical calls and three additional source-access traces. |
| 10 | Goten | `void* ocall_allocate_mem` result rejects; GPU/ML/Eigen and enclave dependency closures were not built. |

No application import is relabeled as an SDK service. No unknown raw SDK/library
call is admitted just to pass compilation. In particular, the analytics OCALLs
are accepted through a generated diagnostic bridge; its remaining crypto and
intrinsic failures are distinct. The independent EH work in progress is not
treated as an accepted sgx-fs capability. These stopping points describe this
campaign, not impossibility of a future port.

## FedServing: bounded integration

Origin is `H-W-Huang/FedServing@da49236c4ae18cf3c9cdde5d8df6fd7505d442c0`.
[Preparation](../apps/fedserving/prepare.py) retains all original combiner
functions and ECALL/OCALL signatures, adds the missing `return 0` from
`init_model_inputs`, adds the pinned SDK `sgx_tstdc.edl` import and changes
`QUERY_SIZE` from 7000 to 16. Six models, ten categories and twenty iterations
remain. Source pins, prepared hashes, adaptations and
[origin/license records](../apps/fedserving/PROVENANCE.md) are retained.

| Configuration | Base | Sequential calls | Full oracle / closure audit |
| --- | --- | ---: | --- |
| BASELINE | `0x40000000` | 6 | PASS |
| RADIX_ONLY | `0x40000000` | 6 | PASS |
| MAC27 | `0x40000000` | 6 | PASS |
| MAC27 high base | `0x140000000` | 6 | PASS |

Each response compares all six weights and 160 prediction values with an
independent Python implementation of the original equations. Zero and identical
predictions exercise the zero-loss branch; four heterogeneous inputs exercise
weight updates. Transport/application returns, unchanged input predictions and
the unwritten iteration field are checked. Five negative controls reject a
wrong prediction, NaN weight, truncated array, missing response and wrong order.
The oracle deliberately retains the upstream repeated `inputs[0].weight`
denominator and output-before-last-update behavior. No numerical algorithm
correction or ML-accuracy claim is implied.

Each image's one application unit and nineteen private formatter/math objects
use the same preset. Ten selected formatter units, the existing helper and eight
newly selected pinned math/classification units use private `app_fmt_` symbols.
No SDK archive is rebuilt or reclassified as application storage. The mandatory
audit verifies consumed source/header/compiler hashes, retained IR, compilation
through placement hashes, exact objects, archive member bytes, SDK archive pins,
bridge inputs/outputs, signed-versus-linked bytes, ownership and ELF permissions,
startup order, signed base/extent, and loaded application page permissions.
BASELINE bridge bytes equal stock Intel output.

Three debugger traces bind the exact protected images to an original 16-byte
vectorized READ in `cal_output` at prepared source line 77. The stack contains
`encbound_require -> cal_output -> turth_discovery -> combine_result ->
sgx_combine_result`. The check returns the original canonical host address and
execution completes all six numerical cases. Those 18 trace calls are separate
from the 24-call functional matrix.

The original `[user_check]` input/output structures remain **caller-chosen
memory** in the normal harness. This trace establishes the exercised
canonical-host check path. It does not establish tagged model storage,
malicious-input rejection, pointer-forgery resistance or general
vulnerability prevention, apart from the narrow enclave-address rejection in
the control below. O2 removes many numerical scratch
arrays; merely linking retained formatter/math code does not exercise every
library path. The 7000-query capacity, KL branch, arbitrary datasets and the
Python/GPU training pipeline remain untested.

### Confused-deputy control

The unchanged `[user_check]` ECALL also admits an enclave-internal pointer.
[The runner](../apps/fedserving/confused_deputy.py) uses the
[probe](../apps/fedserving/confused_deputy.c) against the four fresh images.
BASELINE completes both controls: one ECALL with `output=0x4003d000` writes
1280 bytes of computed predictions into enclave memory; six such writes then a
read ECALL make the enclave read its own memory and return a host-visible
result matching the independent oracle (maximum absolute difference 3.3e-13
write / 3.2e-9 read). RADIX_ONLY, MAC27 and high-base MAC27 trap with SIGILL in
`encbound_abort(ENCBOUND_ERR_POLICY=3)` before the first enclave-internal
access. The write's read-back is a SIM diagnostic; the read result is
host-visible and is the oracle-checked outcome. This is SDK SIM only, uses
`0x3d000` as a scratch target, and establishes pointer confinement for this
ECALL, not arbitrary secret extraction or hardware behaviour. Record:
`build/first10-2026-10-21/fedserving/confused-deputy.json`.

## Wallet: fresh preset validation and narrow audit repair

The existing source pin remains
`asonnino/sgx-wallet@8d15df13e1e37b95d233b3911b5e21ba32a8b962`.
BASELINE, RADIX_ONLY and MAC27 use identical frontend/backend O2 settings,
the full preset and the existing `0x40000000` recipe. Each passes the benign
session including 64 cycles/reconnection, all ten boundary/error cases and
eight original upstream host/test/CLI jobs. Final execution records bind these
jobs to the exact host and signed-image hashes; historical runs are separate.

Four fresh GDB attributions cover both protected profiles and host backing
capacities 16 and 30112 with EDL/allocation size 16. Each stops at RANGE for the
original 30112-byte `ecall_show_wallet` assignment through the modified Intel
bridge. The observed radix matches the 16-byte slot. This remains a range-check
result. Both protected O2 object checks also establish that the matching read
and write checks feed the original memcpy without a bypass entry. No new MAC
forgery experiment or hardware result was performed.

The full preset emits `__encbound_lifecycle_v1` and, in protected objects,
`__encbound_globals_v1`, even for this no-app-data wallet. Its legacy inventory
previously rejected these compiler constants. [The audit correction](../tools/audit_wallet.py)
accepts only exact nonoverlapping eight-byte version-1 data objects in
read-only, nonexecutable ABI sections without relocations, consistent with the
recorded compiler settings. New application globals/functions still reject.
Six actual objects pass; seven controls reject wrong version, writable section,
executable section, disabled setting, injected application data, a function
masquerading as a marker and overlapping markers. Audits leave input bytes
unchanged.

An eighth control damages a retained bridge input and confirms evidence replay
still rejects its hash mismatch. The replay input mapping is internal to the
audit API; ordinary build/CLI audits continue to verify live inputs.

## Reproduction and artifact identity

Use [the campaign commands](../apps/first10/README.md) and
[FedServing recipe](../apps/fedserving/README.md). For the exact recorded
FedServing compiler artifact, run:

```sh
tools/with-integration-defaults.sh python3 apps/fedserving/run.py \
  --plugin build/first10-2026-10-21/toolchain/encbound_pass-final.so
python3 apps/fedserving/trace.py
python3 apps/first10/audit_controls.py
python3 apps/first10/verify.py
```

The final compiler plugin is retained with SHA-256
`233170a8f8d71f46aab14ecc59247dc7136e003fba9ed68fb49a5828895a6eb8`.
All seven successful configurations consumed those bytes. The wallet's existing
pin checks forbid plugin overrides; its manifests keep the normal shared input
path, and the verifier binds that recorded hash to the retained identical
artifact. FedServing explicitly selects the retained path. This isolates saved
evidence from later compiler rebuilds in the shared workspace. Exact consumed
compiler, link and bridge inputs are also copied into a content-addressed local
artifact store. Replay hashes those bytes against the original manifests, then
performs the same closure, ownership, SDK, bridge and image audits. It does not
ignore changed live inputs or rewrite recorded hashes.

The generator's patch record changed during independent work after the tested
images were produced. Regenerating all seven bridges with the recorded generator
binary produced identical output bytes; only that patch input hash changed.
Before/after manifests, commands and byte-equality assertions are retained in
`bridge-refresh.json`. Inventories now identify the refreshed manifests while
the original execution records are preserved. Final functional, overflow and
trace records all match the final signed images.

The final verifier passes **777 saved artifact hashes**, including the 86
application objects/manifests/retained IR, logs, inventories, bridges, image
identities, debugger records and exact retained inputs. It checks consumed
inputs against those retained bytes. Python syntax and targeted whitespace
checks pass; 25 consumed application/source-probe files match their pinned git
objects. No compiler/runtime mechanism implementation changed in this
campaign, so verification focuses on application closures and the repaired
inventory rather than rerunning unrelated feature suites.

All application execution here is **SDK simulation**. EDL admission and compiler
diagnostics are native tool results. No SGX hardware, performance, full
application-pipeline coverage or gate promotion is established.
