# ConFlow hostile-dimension control — 2026-10-22

This record adds fresh application memory-safety controls for the selected
ConFlow softmax ECALLs. It uses the unchanged upstream operator bodies and the
existing four SDK SIM configurations. No ENCBound compiler/runtime mechanism,
pointer representation, protected scope, backend or frozen target changed.

## Finding

`ecall_softmax(input,N,M,C,output)` and
`ecall_softmax_grad(input,grad,N,M,C,output)` allocate enclave scratch from `N`
and then index it as `M` rows of `C` elements. Nothing validates `N == M*C`,
and `M`/`C` are signed scalars. Two malformed-dimension cases follow directly:

| Case | Index | `ecall_softmax` source / prepared | `ecall_softmax_grad` source / prepared |
| --- | --- | --- | --- |
| `N < M*C` (for example `N=4,M=1,C=5`) | `x[i*C+j]` past the allocation | `Enclave.cpp:2213` / `359` | `Enclave.cpp:2290` / `436` |
| negative `C` (for example `N=4,M=2,C=-1`) | `x[i*C]` before the allocation | `Enclave.cpp:2211` / `357` | `Enclave.cpp:2288` / `434` |

The host input and gradient arrays are complete; only the scalar dimensions
disagree. The first case crosses the end of the 16-byte scratch slot. The second
makes `i*C` negative at `i=1`, so the load occurs before the allocation.

This is an application bug (CWE-787/CWE-125), not a mechanism change. A hostile
host is not trusted for enclave memory safety, so the missing shape/sign
validation is a real boundary-validation gap. It is also exactly the case a
bounded access mechanism can contain without application cooperation.

## Fresh direct SDK SIM results

The new `host/vuln-host` driver is separate from the functional `host/host`; it
uses the original generated ECALL adapters. `valid` is `N=4,M=1,C=4`;
`positive` is `N=4,M=1,C=5`; `negative` is `N=4,M=2,C=-1`.

`ecall_softmax`:

| Configuration | valid | positive shape | negative `C` |
| --- | --- | --- | --- |
| BASELINE `0x40000000` | return 0 | SIGSEGV (`-11`) | return 0 |
| RADIX_ONLY `0x40000000` | return 0 | return 0 | SIGILL (`-4`) |
| MAC27 `0x40000000` | return 0 | SIGILL (`-4`) | SIGILL (`-4`) |
| MAC27 `0x140000000` | return 0 | SIGILL (`-4`) | SIGILL (`-4`) |

`ecall_softmax_grad` has the same pattern:

| Configuration | valid | positive shape | negative `C` |
| --- | --- | --- | --- |
| BASELINE `0x40000000` | return 0 | SIGSEGV (`-11`) | return 0 |
| RADIX_ONLY `0x40000000` | return 0 | return 0 | SIGILL (`-4`) |
| MAC27 `0x40000000` | return 0 | SIGILL (`-4`) | SIGILL (`-4`) |
| MAC27 `0x140000000` | return 0 | SIGILL (`-4`) | SIGILL (`-4`) |

The two checked profiles reject the cases with different categories:

* **Positive shape, MAC27:** `encbound_abort (code=5)`
  (`ENCBOUND_ERR_TAG`). The overrun lands in the adjacent slot, which has the
  same radix; RADIX_ONLY accepts it because it does not authenticate slot
  identity. MAC27 rejects the first out-of-slot read before the load.
* **Negative `C`, RADIX_ONLY and MAC27:** `encbound_abort (code=3)`
  (`ENCBOUND_ERR_POLICY`). The preceding slot base is outside the protected
  heap region, so the region check rejects the access before the load.
  BASELINE returns success for this case: the out-of-bounds under-read is
  silent.

Fresh debugger attribution for normal-base MAC27 (high-base is identical):

```text
encbound_abort (code=5) at sdk/platform_layout.c:459
#1  encbound_require (...) at runtime/capability.c:186
#2  ecall_softmax (..., N=4, M=1, C=5, ...) at prepared/Enclave.cpp:359
```

```text
encbound_abort (code=5) at sdk/platform_layout.c:459
#1  encbound_require (...) at runtime/capability.c:186
#2  ecall_softmax_grad (..., N=4, M=1, C=5, ...) at prepared/Enclave.cpp:436
```

```text
encbound_abort (code=3) at sdk/platform_layout.c:459
#1  encbound_require (...) at runtime/capability.c:186
#2  ecall_softmax (..., N=4, M=2, C=-1, ...) at prepared/Enclave.cpp:357
```

```text
encbound_abort (code=3) at sdk/platform_layout.c:459
#1  encbound_require (...) at runtime/capability.c:186
#2  ecall_softmax_grad (..., N=4, M=2, C=-1, ...) at prepared/Enclave.cpp:434
```

The checks fire before the corresponding loads execute; the aborts are
attributed to the upstream `x[i*C]`/`x[i*C+j]` accesses, not to a loader or
unrelated fault. The prepared lines are the byte-pinned upstream bodies used by
the functional matrix.

## Independent native controls

`apps/conflow/vuln.py` also records native controls under
`build/conflow/vuln`:

* **AddressSanitizer on the uninstrumented prepared bodies.** Both the positive
  and negative cases report `heap-buffer-overflow`, `READ of size 4`, with a
  16-byte allocation. The positive report is at the `x[i*C+j]` access; the
  negative report says the address is `4 bytes before` the region and points at
  `x[i*C]`. This independently confirms both out-of-object accesses without
  ENCBound.
* **The same bodies through `tools/encbound-cc.sh` and the real checked
  runtime on `tests/fake_platform.c`.** The application runs on the fake
  protected stack. RADIX_ONLY accepts valid and positive-shape calls and
  rejects the negative case; MAC27 accepts the valid shape and aborts the
  positive shape with `ABORT code=5`. The native driver decodes the capability
  passed to the `sgx_read_rand` stand-in; it is a control harness, not an SDK
  service.

## Additional source-review observation

The same unvalidated `N/M/C` indexing pattern appears in four other pinned
operators that are not part of the selected EDL closure:

| Operator | Illustrative source line |
| --- | ---: |
| `ecall_logloss` | `Enclave.cpp:363` (out-of-range reads feed `output[0]`) |
| `ecall_logloss_grad` | `Enclave.cpp:534`, `:541`, `:547` |
| `ecall_softmax_cross_entropy` | `Enclave.cpp:6382`, `:6389`, `:6397` |
| `ecall_softmax_cross_entropy_grad` | `Enclave.cpp:6440`, `:6447`, `:6453` |

These were found by source review only. They were not compiled, added to the
EDL closure, or executed for this record. They are listed because a future
ConFlow integration should not assume that the selected softmax pair is the
only operator with this shape relation. `ecall_logloss` is especially worth
revisiting because its out-of-range reads are folded into a host-visible loss
value rather than only causing a later write/crash.

## Functional regression

The unchanged functional host was rerun after the new driver/Makefile files
were added. All four configurations still pass `384` sequential ECALLs and
`2,520` element comparisons per configuration:

```json
{"result":"PASS","calls":384,"comparisons":2520,"rounds":3,"fixtures":8}
```

The application object and prepared operator bodies were not changed; the
Makefile dependency rebuilt them because the recipe file changed. The fresh
functional JSON is in the machine-readable record.

## Reproduction

```sh
python3 apps/conflow/vuln.py --evidence evidence/2026-10-22-conflow-shape-vuln.json
```

The script rebuilds and audits the four matched configurations, builds the
separate `vuln-host` target, runs the direct matrix, records debugger
attribution, and runs the native ASan and checked-runtime controls. Logs and
the full result record remain under `build/conflow/vuln/`; the optional
`--evidence` argument refreshes this record.

## Scope and limits

* This is SDK SIM plus native control evidence. No hardware, timing, exploit,
  information-leak or full TensorFlow/DeepCrossing/ConFlow claim is made.
* The malformed input is a complete array with inconsistent or negative
  `N/M/C`; the `user_check` arrays themselves remain host memory.
* The positive-shape overrun crosses a 16-byte protected slot. ENCBound does
  not promise sub-slot object bounds; an overrun that remains inside the
  rounded slot would not be rejected.
* The negative case is rejected as `POLICY` because the preceding slot base is
  outside the protected heap region in these runs. That category can depend on
  allocation placement; it is not a claim that every negative index is caught
  by the same category.
* RADIX_ONLY accepting the positive same-radix adjacent slot is expected from
  the existing profile definition. It rejects the negative underflow, while
  MAC27 rejects both.
* `ecall_logloss`, `ecall_logloss_grad`, `ecall_softmax_cross_entropy` and
  `ecall_softmax_cross_entropy_grad` contain the same unvalidated `N/M/C`
  indexing pattern in the pinned source, but are outside the selected closure
  and were not compiled or executed for this record.
* The native checked-runtime path admits the selected math externals and uses
  the control harness; it does not replace the SDK SIM matrix as the
  application result.

## Identities

* Pinned upstream `conflow-dev/ConFlow` at
  `fd1904271e127980c1c2a7a813a1c506266f7372`.
* Upstream `sgx_tf_ops/Enclave/Enclave.cpp` SHA-256
  `a57781c526708d746646074685db65ab1e82c767ca8dbcfad8f1e9a136a66d4e`.
* Prepared operator file SHA-256
  `89fc9a49720a25e8f4ea3891d425a4801c1927137c5c24b182f33db1c7899f75`.
* Input/control source hashes and every retained log hash are in
  [the machine-readable record](2026-10-22-conflow-shape-vuln.json).
