# ConFlow direct `[user_check]` pointer forgery — 2026-10-22

This record adds a direct confused-deputy control to the selected ConFlow
operators. It uses the unchanged upstream ECALLs and the existing four SDK SIM
configurations. It is deliberately separate from the
[hostile-dimension softmax control](2026-10-22-conflow-shape-vuln.md): that case
is an out-of-bounds index inside an enclave allocation, whereas this case is a
host-supplied pointer value that names enclave memory.

No ENCBound compiler/runtime mechanism, EDL declaration, protected scope,
backend or frozen target changed.

## Finding

The original EDL keeps `[user_check]` on both pointer arguments:

```text
sgx_tf_ops/Enclave/Enclave.edl:36
public void ecall_encrypt([user_check]float *input,int N, [user_check]float *output);
sgx_tf_ops/Enclave/Enclave.edl:37
public void ecall_decrypt([user_check]float *input,int N, [user_check]float *output);
```

`[user_check]` passes the host-chosen raw pointer with no bridge copy, length,
null, canonical or range check. The enclave then stores through it:

```text
sgx_tf_ops/Enclave/Enclave.cpp:198
output[i] =(input[i % N] - gaussrand(mean, std))/static_cast<float>(Nt+1);
```

The prepared copy is at `prepared/Enclave.cpp:49`. `N`, `Ne`, `insert` and
`indexs` determine the write extent; with the upstream `Ne=5` and `N=4`, one
`ecall_encrypt` writes 20 floats (80 bytes). The function does not call
`sgx_is_outside_enclave` or validate a range.

A host that names a writable enclave address as `output` therefore makes
trusted enclave code write its own share values into enclave memory. Naming the
same address as the later `ecall_decrypt` input makes the enclave read those
bytes back and return the original four floats through a host output buffer.
That is a direct confused-deputy write followed by a read-back, not an
out-of-bounds index and not an OCALL return value.

## Fresh direct SDK SIM results

The new `host/cd-host` driver is separate from the functional `host/host` and
the hostile-shape `host/vuln-host`. It reads a writable section from the image's
own section table, validates the chosen range against `/proc/self/maps`, and
uses the base supplied by `ENCBOUND_TEST_BASE`. In BASELINE the selected section
is `.encbound.appbss`; protected images keep the equivalent storage in `.bss`.
Only BASELINE reaches the store.

| Configuration | control (host buffers) | direct forgery (enclave address) |
| --- | --- | --- |
| BASELINE `0x40000000` | return 0, readback PASS | return 0, readback PASS, target `0x40033914` |
| RADIX_ONLY `0x40000000` | return 0, readback PASS | SIGILL (`-4`) |
| MAC27 `0x40000000` | return 0, readback PASS | SIGILL (`-4`) |
| MAC27 `0x140000000` | return 0, readback PASS | SIGILL (`-4`) |

The baseline log is:

```text
{"mode":"cd","status":0,"target":"0x40033914","readback":"PASS","first":1.25}
```

`ecall_encrypt` wrote the 20 share floats into the enclave image's own writable
section, and `ecall_decrypt` read them back and recovered the four inputs
(`1.25, 2.5, 3.75, 5.0`) within tolerance. The control row uses ordinary host
buffers and passes in every configuration.

## Attribution

Fresh debugger attribution for the protected profiles:

```text
encbound_abort (code=3) at sdk/platform_layout.c:459
#1  encbound_require (...) at runtime/capability.c:186
#2  ecall_encrypt (..., output=0x40043848 <mparams+40>)
      at prepared/Enclave.cpp:49
#3  sgx_ecall_encrypt (...) at generated/Enclave_t.c:135
```

The high-base MAC27 row is identical with `output=0x140043848` and
`0x140001524` for `ecall_encrypt`. The abort fires at the first
`output[i] = ...` store, before the write executes. `code=3` is
`ENCBOUND_ERR_POLICY`, the same category the FedServing confused-deputy control
uses for an unminted enclave pointer.

## Relationship to the softmax shape control

| Control | Host input | Rejected access | Class |
| --- | --- | --- | --- |
| [softmax shape](2026-10-22-conflow-shape-vuln.md) | complete arrays; inconsistent `N/M/C` | `x[i*C+j]` past a 16-byte slot | OOB index in an enclave allocation |
| this record | pointer value names an enclave address | `output[i]` through the `[user_check]` argument | direct pointer forgery / confused deputy |

The shape control is an application arithmetic error. This control is the
boundary-annotation error itself: the host directly selects the memory that
trusted code will read or write.

## Scope and limits

* SDK SIM plus SDK debugger attribution. No SGX hardware, timing, arbitrary
  address sweep, secret extraction or code execution is claimed.
* The host knows the enclave base and the image's writable sections in SIM, as
  a real SGX loader does. Selecting one writable section demonstrates the
  primitive; it is not a claim that every enclave address is writable or that a
  particular production secret is reachable.
* Only 80 bytes are written (20 floats) and only four floats are read back.
  This is a bounded control, not an unbounded write gadget.
* The functional 1,536-call matrix and the hostile-shape control are unchanged.
  This new driver does not alter the application, prepared operator bodies, EDL
  or generated bridge.

## Reproduction

```sh
python3 apps/conflow/confused_deputy.py --trace
python3 apps/conflow/confused_deputy.py --skip-build --trace \
  --evidence evidence/2026-10-22-conflow-user-check-confused-deputy.json
```

Logs and the driver live under `build/conflow/confused-deputy/`. The
machine-readable record is
[2026-10-22-conflow-user-check-confused-deputy.json](2026-10-22-conflow-user-check-confused-deputy.json).

## Fresh same-day reproduction — 2026-10-22

A later reproduction re-ran the driver against the existing four matched builds
with fresh logs under `build/conflow/confused-deputy-fresh/` (a separate
directory; the recorded `build/conflow/confused-deputy/` artifacts and their
hashes are untouched). All recorded outcomes repeat:

* BASELINE direct forgery returns 0 with target `0x40033914`, read-back
  `PASS`, first recovered float `1.25`; all four control rows return 0 with
  read-back `PASS`.
* The three protected forgery rows produce no output and terminate with SIGILL
  (process exit 132; the driver asserts the `-4` signal returncode).
* Fresh gdb attribution in RADIX_ONLY, MAC27 and high-base MAC27 again shows
  `encbound_abort (code=3)` at `sdk/platform_layout.c:459` from
  `encbound_require` (`runtime/capability.c:186`) at `ecall_encrypt`,
  `prepared/Enclave.cpp:49`, with `output=<mparams+40>` through the
  `.bss` fallback (`0x40043848`, `0x140043848` at the high base). A `readelf`
  check confirms the selection: the BASELINE image's
  `.encbound.appbss` is `[0x33000, 0x33964)` so `base + size - 80 = 0x40033914`,
  and the protected images have no `.encbound.appbss`, so the driver takes the
  tail of `.bss` (`[0x43020, 0x43898)` → `0x40043848`).
* The functional 384-call matrix re-ran PASS in all four configurations
  (384 calls / 2,520 comparisons per profile; the fresh record is
  `build/conflow/results-fresh.json`, not a rewrite of the recorded
  `build/conflow/results.json`).

One driver correction was needed to complete reproduction: the final artifact
listing now uses the existing `rel()` helper, so a relative `--out` no longer
crashes while writing the summary JSON. No application, image, EDL or result
changed.

## Identities

* Pinned upstream `conflow-dev/ConFlow` at
  `fd1904271e127980c1c2a7a813a1c506266f7372`.
* Upstream `sgx_tf_ops/Enclave/Enclave.cpp` SHA-256
  `a57781c526708d746646074685db65ab1e82c767ca8dbcfad8f1e9a136a66d4e`.
* Prepared operator file SHA-256
  `89fc9a49720a25e8f4ea3891d425a4801c1927137c5c24b182f33db1c7899f75`.
* Driver, commands, log hashes and per-profile outcomes are in the JSON record.
