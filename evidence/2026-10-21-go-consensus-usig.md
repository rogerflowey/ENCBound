# go-consensus USIG integration — 2026-10-21

The owner requested an integration attempt of `ibalajiarun/go-consensus`'s USIG
component and a report if non-trivial ENCBound changes were needed. The pinned
five-entry component now passes **four complete SDK SIM configurations / 324
normal ECALLs**, with **76 Ed25519 signatures, 28 P-256 signatures and 52 HMAC
outputs independently verified with OpenSSL**. No non-trivial mechanism extension
was needed. This is a serial native-host ECALL integration, not a distributed
consensus or Go/cgo deployment result.

[Recipe and reproduction](../apps/go-consensus-usig/README.md),
[exact SDK contracts](../apps/go-consensus-usig/CONTRACTS.md),
[source/license origins](../apps/go-consensus-usig/PROVENANCE.md) and
[the machine-readable evidence](2026-10-21-go-consensus-usig.json) accompany this
record. Source is pinned at `3a733ffd036a5b66d578f9002fca76ede40f8d47`;
29 selected files and the archive are hash-checked. Earlier shortlist findings
remain source/generator evidence with their original scope.

## Changes and integration scope

Every application/dependency object uses `config/integration.env`, including
protected writable globals, lifecycle, callbacks, atomics, aggregate ABI, variadic
normalization and VLA support. Both protected profiles use the same settings;
BASELINE uses the matched application/library configuration with ordinary
pointers. No-EH mode is explicit, as are cleared GEP flags and no post-pass
InstCombine. Frontend and machine code use O2. USIG and crypto units use the
matched scalar frontend, while the private library recipes retain their own
recorded flags. Reuse, local proofs and fast paths stay off.

The application closure includes the original USIG C++ unit, all six crypto C
units listed by its Makefile, one application-owned missing-helper unit, 26
private libc++ and 11 formatter objects. Protected profiles also include the
generated application record adapter: **45 objects in BASELINE, 46 in each
protected build; 183 across the matrix**. Application constructor/destructor,
container, formatter and crypto bodies stay instrumented. Trusted SDK, bridge,
early-bootstrap and exact service adapters retain separate ownership. The
protected global key arrays and vector object use individual GLOBAL slots;
read-only curve tables retain the existing RO COMPAT treatment.

The only core correction is in `pass/encbound_cxx_eh.h`: the EH output verifier
was unconditionally requiring an EH boundary wrapper for `encbound_cxx_atexit`,
including the established no-exception lifecycle configuration. USIG's global
vector exposed that regression. The corrected verifier accepts the existing
owned direct C `void(void*)` destructor in no-EH mode, checks registration ABI,
callback ownership and required switches, and still requires a boundary wrapper
when EH is enabled. Unknown, runtime-selected and wrong-ABI callbacks reject.
This does not enable exceptions, change startup scheduling or expose SDK state.

Application-specific ECDSA/HMAC/random adapters validate complete application
ranges before calling the unchanged pinned IPP SDK. A four-slot private token
table retains actual ECDSA context pointers; application code receives only
integer tokens. HMAC checks the complete positive output extent even on SDK
failure, because the SDK's error cleanup clears `mac_len` bytes. SDK errors are
preserved and no unknown raw application SDK call is admitted.

The explicit build adaptations are:

1. Rename the unused application `printf` definition/declaration to
   `app_usig_printf`, preserving its body and the exercised `debug` formatter.
2. Add the real pinned SDK-only `sgx_tstdc.edl` import for runtime services. The
   original five ECALL signatures and print OCALL stay unchanged; no application
   thread call is admitted. BASELINE's four emitted bridge files match stock
   generation of this adapted EDL byte-for-byte.
3. Build the six original `.c` crypto files as C99 and add C linkage to the
   C++ caller's API header. The upstream C++ build route creates a mutable LLVM
   declaration for an external const aggregate whose definition is read-only;
   ENCBound then requests a nonexistent writable-global capability cell at link.
   The recorded C build port resolves this without changing crypto bodies or
   disabling protected globals. General C++ external-const reconciliation is
   not implemented by this integration.
4. Complete missing `randombytes`/`crypto_verify_32` definitions as ordinary
   application code, with new native helper tests and origin records. Neither
   helper is reached by the five original ECALLs, but both remain compiled and
   audited in the closure.
5. Record `-fno-vectorize -fno-slp-vectorize` for USIG/crypto in all profiles.
   Fresh default-vectorized admission still rejects `llvm.vector.reduce.and.v4i32`
   in `fe25519_iszero` and `llvm.vector.reduce.or.v4i32` in `crypto_verify_32`.
   The diagnostic build exits with failure; it is not a passing integration.

No pointer format, threat model, protected scope, backend, SDK/application data
boundary or frozen experiment target changes. The new adapters use the existing
trusted-service extension route.

## Functional and closure evidence

| Configuration | Base | Normal ECALLs | Ed25519 / P-256 / HMAC verified | Application objects | Static require calls |
| --- | --- | --- | --- | --- | --- |
| BASELINE | `0x40000000` | 81 | 19 / 7 / 13 | 45 | 0 |
| RADIX_ONLY | `0x40000000` | 81 | 19 / 7 / 13 | 46 | 7,225 |
| MAC27 | `0x40000000` | 81 | 19 / 7 / 13 | 46 | 7,225 |
| MAC27 | `0x140000000` | 81 | 19 / 7 / 13 | 46 | 7,225 |

The oracle checks before-init errors, successful init, repeat-init rejection,
three independently advancing counters, six signing/MAC rounds, altered MAC /
digest / counter rejection, truncated MAC lengths, zero/oversized output errors,
recovery and the original `strncpy` behavior for a binary HMAC key with a NUL.
A second freshly created enclave establishes a new session with counter one.
Signatures are checked over the exact message bytes; ECDSA verification handles
the SDK's little-endian limbs and SHA256 signing semantics. Modified signature
messages also fail the independent verifier. Entire MACs and untouched host
output tails are checked, rather than accepting only application status.

Four complete closure audits check all preset settings, compiler/plugin/input
hashes, retained input/checked IR, object placement, undefined application calls,
SDK archive identity, signed-image input, early-bootstrap order, app/SDK symbol
separation and app data ownership. Loaded RO/RELRO/RW permissions pass: four
app-data ranges in BASELINE and six in each protected image. Each protected
configuration also has a debugger trace of a tagged four-byte read in original
`fe25519_add`, including raw-address conversion and completion of the full
functional oracle. Static check counts do not establish dynamic coverage of all
units/functions.

## Malformed-input and resource controls

Five separate modes run through original ECALLs in fresh enclaves; each has both
direct execution and GDB attribution. No protective input validation is added
to the application to obtain these outcomes.

| Input | BASELINE | RADIX_ONLY | MAC27 at either base |
| --- | --- | --- | --- |
| MAC key length 1,025 into a 1,024-byte global | Watchpoint observes adjacent-byte write in original `strncpy`; returns success | `encbound_strncpy` destination RANGE (4), source line 129 | Same RANGE |
| Ed25519 key length 1,024, then original NUL store | Watchpoint observes one-past write; returns success | Watchpoint observes one-past write; returns success | TAG (5) at original store, source line 134 |
| Counter ID 4 after three-counter init | Existing libc++ `vector[]` assertion | Same assertion | Same assertion |
| Zero counters followed by create-MAC | Existing libc++ `vector[]` assertion | Same assertion | Same assertion |
| Init requests 67,108,864 counters | Terminal C++ new failure | RESOURCE (7) through `encbound_cxx_new` | Same RESOURCE |

The NUL store advances a capability to the next aligned slot. RADIX_ONLY lacks
authentication to the original slot; MAC27's slot MAC mismatches in the observed
runs. GDB read/write watchpoints and the stopped instruction establish even the
unchanged zero-byte store; direct runs return normally in the accepting cases.
The affected byte is subsequently overwritten by the original private-key copy,
so no sustained key corruption, disclosure or exploit is claimed. This is a
bounded SDK SIM authentication contrast, not a general protection rate.

The bad-counter/zero-counter failures come from the matched libc++ assertion,
also present in BASELINE; they are not ENCBound spatial protection. Allocation
exhaustion is terminal resource behavior, not a graceful application error or a
memory-protection result.

Native tests with the real runtime and recording SDK stand-ins pass **81
RADIX_ONLY checks and 83 MAC27 checks**. They cover context exhaustion, invalid /
closed / raw handles, open/close failure behavior, interior extents, full HMAC
error-cleanup extents, NULL/signed lengths, stripped/trusted pointers and MAC
corruption before raw SDK dispatch. Separate helper tests cover equal/different
32-byte values at every byte, random output bounds, zero length and SDK error
termination. These native stand-ins do not establish real crypto behavior;
the independent SDK SIM oracle supplies that evidence.

The verifier correction also passes **24 lifecycle admission controls**, **47
EH admission/output controls**, the existing compiler/pass regression suite and
**16 matched lifecycle SDK SIM configurations**. These are fresh regressions;
their calls are not added to the 324 USIG total.

## Reproduction and remaining limits

Run the prerequisite builds and verifier/lifecycle regression commands in the
[recipe](../apps/go-consensus-usig/README.md#reproduce) before collecting evidence.
The collector requires their four retained logs as well as the USIG matrix.

```sh
python3 apps/go-consensus-usig/run.py
python3 apps/go-consensus-usig/record.py \
  --build-root build/go-consensus-usig/all-compat-v1 \
  --output evidence/2026-10-21-go-consensus-usig.json
python3 apps/go-consensus-usig/record.py \
  --verify evidence/2026-10-21-go-consensus-usig.json
```

The JSON binds exact commands, source/SDK identities, current recipe files,
application/library manifests, artifacts, logs, native tests and debugger traces.
The output tree is `build/go-consensus-usig/all-compat-v1/`. The recipe documents
local tool/SDK prerequisites and a selectable fresh replay directory.

No unresolved blocker remains for this selected serial closure. Using the
upstream C++ compilation of its C crypto or default vectorized frontend still
requires further compiler compatibility work; those routes are not claimed.
The original Go/cgo wrapper, distributed use, concurrency/TLS, automatic hardware
startup/teardown, performance, full memory accounting, protocol/rollback safety,
constant-time assurance and crypto conformance remain unestablished. USIG's
vector stores allocated atomic pointers without deleting their pointees;
complete lifecycle reclamation is not claimed. SIM does not automatically run
its registered destructors, and this recipe does not relabel enclave destruction
as a destructor-coverage result. No frozen gate is promoted by this supplemental
integration.
