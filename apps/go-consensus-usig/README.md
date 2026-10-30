# go-consensus USIG enclave integration

Pinned `ibalajiarun/go-consensus` USIG at
`3a733ffd036a5b66d578f9002fca76ede40f8d47` runs a serial direct-ECALL workflow
in Intel SDK 2.26 simulation. BASELINE, RADIX_ONLY, MAC27 and high-base MAC27
pass the same 81-call oracle. This integrates the five-entry USIG component;
the Go/cgo wrapper, distributed DuoBFT deployment, concurrency, rollback safety,
SGX hardware and performance are not established.

No non-trivial ENCBound mechanism change was needed. A small verifier correction
restores the already-supported no-exception destructor-registration ABI; new
application-specific checked ECDSA/HMAC adapters follow existing SDK handle and
buffer rules. See [boundary contracts](CONTRACTS.md), [source origins](PROVENANCE.md)
and [evidence and limits](../../evidence/2026-10-21-go-consensus-usig.md).

## Reproduce

From the restart root with the existing pinned SDK 2.26 installation and
Clang/LLVM 21, Python 3, GCC, OpenSSL development files and GDB:

```sh
make -C pass
make -C tools/edger8r
mkdir -p build/go-consensus-usig
python3 tests/cxx-lifecycle/admission.py > build/go-consensus-usig/lifecycle-admission.log 2>&1
python3 tests/cxx-eh-rtti/admission.py > build/go-consensus-usig/eh-admission.log 2>&1
make -C pass test > build/go-consensus-usig/pass-regression.log 2>&1
python3 tests/cxx-lifecycle/run.py > build/go-consensus-usig/lifecycle-sim.log 2>&1
python3 apps/go-consensus-usig/run.py
python3 apps/go-consensus-usig/record.py \
  --build-root build/go-consensus-usig/all-compat-v1 \
  --output evidence/2026-10-21-go-consensus-usig.json
python3 apps/go-consensus-usig/record.py \
  --verify evidence/2026-10-21-go-consensus-usig.json
```

`prepare.py` downloads a hash-pinned archive into `build/go-consensus-usig/` if
needed. SDK paths are explicit in `build.py`/`finish.py`. Only recipe-local
prepared copies are changed. `run.py` retains every build/normal/diagnostic log,
exact commands, original and checked IR, object placement, signing metadata and
source identities. GDB needs permission to trace its child processes. A fresh
build can be selected with `--out build/go-consensus-usig/replay`.
Pass that same path to `record.py --build-root`. The collector also checks the
four verifier/lifecycle regression logs at the fixed paths above; those tests
are separate from the 324 USIG ECALLs.

A single build can be run with:

```sh
python3 apps/go-consensus-usig/build.py --profile MAC27 \
  --out build/go-consensus-usig/single
```

The builder applies `config/integration.env` to every application/library object.
No-EH, retained-GEP and no post-instrumentation InstCombine are explicit. Frontend
and code generation use O2; USIG/crypto units use `-fno-vectorize
-fno-slp-vectorize` in every profile. The default vectorized diagnostic visibly
rejects `llvm.vector.reduce.and.v4i32` in `fe25519` and
`llvm.vector.reduce.or.v4i32` in the supplied compare helper. No intrinsic is
silently exempted. The existing private libc++ and formatter recipes retain their
own recorded frontend flags.

## Port and closure

- The C++ USIG unit, all six listed Ed25519 C units, and a small missing-helper
  unit remain application code, alongside 26 private libc++ and 11 formatter
  objects. Protected profiles add the generated application value adapter:
  45 application objects in BASELINE and 46 in each protected build.
- Original ECALL declarations and print OCALL remain. A pinned SDK-only
  `sgx_tstdc.edl` import supplies SDK runtime OCALLs. BASELINE's four generated
  files are byte-identical to stock generation of this explicitly adapted EDL.
- Rename the unused application `printf` definition/declaration to
  `app_usig_printf` to avoid collision with the SDK. Retain its body and the
  exercised `debug` formatter; `vsnprintf` uses the private instrumented formatter.
- Compile the six `.c` files as C99 with an `extern "C"` API in `crypto_api.h`.
  Upstream compiles them as C++; that route exposes an external aggregate-const
  IR mismatch (mutable declaration versus read-only definition) and fails the
  protected-global link. This is an explicit build port, with unchanged C bodies.
- Supply the upstream Makefile's missing `randombytes` and `crypto_verify_32`
  definitions as application code. Neither is reached by the five ECALLs;
  separate native tests verify their functional behavior. They are still
  instrumented and audited in the complete closure.
- Trusted ECDSA contexts remain private behind four integer tokens. Exact
  buffer contracts cover signature output and HMAC error-cleanup writes. Private
  SDK memory is never made application-accessible.

Audits check every preset setting, source/IR/object/placement hash, SDK archive,
undefined application reference, bootstrap order and loaded data permissions.
Protected images contain 7,225 `encbound_require` call sites across the closure;
this static count is not dynamic coverage. GDB independently observes a successful
tagged four-byte read in original `fe25519_add` in each protected configuration.

## Workload and separate controls

The 81-call workflow covers before-init errors, successful init, repeat-init
rejection, three persistent atomic counters, independent OpenSSL Ed25519/P-256
verification, exact HMAC bytes, altered MAC/digest/counter rejection, truncated
MACs, invalid output sizes and recovery. A second enclave checks the original
`strncpy` behavior for a binary HMAC key containing NUL. Per configuration:
19 Ed25519 signatures, 7 ECDSA signatures and 13 HMAC outputs are verified.

Five separate fresh-enclave controls preserve the original source behavior:

| Input | BASELINE | RADIX_ONLY | MAC27, both bases |
| --- | --- | --- | --- |
| 1,025-byte MAC key into 1,024-byte global | Watchpoint observes write beyond global; returns success | Checked `strncpy` RANGE | Checked `strncpy` RANGE |
| 1,024-byte Ed25519 key followed by original NUL store | One-past write observed; returns success | One-past write observed; returns success | Original store rejects TAG |
| Counter ID 4 with three counters | libc++ assertion | Same assertion | Same assertion |
| Zero counters, then create MAC | libc++ assertion | Same assertion | Same assertion |
| 67,108,864 counters | Terminal `new` allocation failure | Terminal RESOURCE (7) | Terminal RESOURCE (7) |

The one-past pointer derives a new aligned slot address. RADIX_ONLY has no MAC
binding to the original slot; MAC27 rejects that authentication mismatch. This
is a bounded observed contrast, not universal overflow protection or an exploit.
The accepted NUL write is subsequently overwritten by the original private-key
copy. Assertions and allocation failures are not spatial-protection results.
Native adapter tests use recording SDK stand-ins with the real ENCBound runtime;
real crypto behavior comes from the separate SIM oracle.

## Vulnerability dig and release diagnostics — 2026-10-22

The pinned application unit was screened for host-controlled memory-safety
errors. Native ASan on the unmodified source establishes four findings:
caller-sized copies into `usig_mac_key` and `edd25519_sk` (lines 129, 132 and
the original line 134 NUL store), and an unchecked `usig_counters[ctr_id]`
index (line 264). See [the dig](vuln/README.md) and
[the record](../../evidence/2026-10-22-usig-vulns.md).

```sh
python3 apps/go-consensus-usig/vuln/run.py
python3 apps/go-consensus-usig/vuln/run.py --verify
```

The default build stops the counter index in a libc++/C assertion, which is an
availability result, not spatial protection. A supplementary release diagnostic
builds only the application units with `-DNDEBUG` and drives the same original
ECALL:

```sh
python3 apps/go-consensus-usig/build_noassert.py --profile BASELINE   --out build/go-consensus-usig/noassert-v1/BASELINE
python3 apps/go-consensus-usig/build_noassert.py --profile RADIX_ONLY --out build/go-consensus-usig/noassert-v1/RADIX_ONLY
python3 apps/go-consensus-usig/build_noassert.py --profile MAC27      --out build/go-consensus-usig/noassert-v1/MAC27
python3 apps/go-consensus-usig/release_control.py
python3 apps/go-consensus-usig/release_control.py --verify
```

BASELINE and RADIX_ONLY crash on the out-of-bounds element load/`fetch_add`;
MAC27 rejects the tagged pointer with `code=5` at line 264. This is a
supplementary diagnostic, not a fifth matrix configuration. See
[the release control record](../../evidence/2026-10-22-usig-release-control.md).

A second consequence control uses the existing four images. A MAC key length
that reaches `edd25519_sk` replaces the signing key in BASELINE (the host
verifies the signature with the attacker key and checks that the legitimate key
fails); every protected profile stops at the checked `strncpy` with
`ENCBOUND_ERR_RANGE` (`code=4`):

```sh
python3 apps/go-consensus-usig/key_replace.py
python3 apps/go-consensus-usig/key_replace.py --verify
```

See [the key-replacement record](../../evidence/2026-10-22-usig-key-replace.md).
No pointer mechanism, protected scope, trusted boundary, backend or frozen
experiment target changed.

