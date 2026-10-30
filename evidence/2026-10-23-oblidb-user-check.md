# ObliDB direct `[user_check]` pointer forgery — 2026-10-23

This record adds a direct confused-deputy control to the bounded ObliDB
linear-scan workload. It uses the unchanged upstream ECALL body and the existing
matched SDK SIM configurations. The functional block workload and the
`[user_check]` control are kept separate; no EDL declaration, application body,
ENCBound mechanism, protected scope, trusted boundary, backend or frozen target
changed.

## Finding

The original EDL keeps `[user_check]` on the block pointer:

```text
isv_enclave/isv_enclave.edl:109
public int opOneLinearScanBlock(int structureId, int index,
                                [user_check]Linear_Scan_Block* block, int write);
```

The unchanged upstream body is at `isv_enclave/enclave_data_structures.cpp:43`.
It first reads 512 bytes from `block` in an unconditional copy, then writes 512
bytes back on a read:

```text
prepared/enclave_data_structures.cpp:88
memcpy(real->data, block, BLOCK_DATA_SIZE);

prepared/enclave_data_structures.cpp:111
if(!write) memcpy(block, real->data, BLOCK_DATA_SIZE);
```

`[user_check]` passes the host-chosen raw pointer with no bridge copy, length,
null, canonical or outside-enclave check. The body does not call
`sgx_is_outside_enclave` or validate a range. A host that names an
enclave-internal address therefore makes the enclave read that address into a
block and, on the read path, write decrypted block bytes to it.

The control names the image's own `linOramCache` global. It first stores a known
pattern in block 0 through a host buffer, then:

1. reads block 0 into `linOramCache` (`write=0`), which performs the enclave
   read at `:88` and the write at `:111` in BASELINE;
2. writes `linOramCache` into block 1 (`write=1`), the enclave read at `:88`;
3. reads block 1 back through a normal host buffer.

The `linOramCache` target is not used by the selected linear path because
`MIXED_USE_MODE=0`, so the BASELINE read-back is attributable to the two
`opOneLinearScanBlock` calls. The generated block store remains host memory.

## Fresh direct SDK SIM results

The new `host/uc-host` driver is separate from the functional `host/host`. It
finds `linOramCache` in the image's own `.symtab` and validates the chosen span
against `/proc/self/maps`; it does not assume a fixed scratch offset. Only
BASELINE reaches the copies. The `control` mode runs the same ECALL pair with
host buffers and passes in every configuration.

| Configuration | `control` (host buffers) | `cd` (enclave address) |
| --- | --- | --- |
| BASELINE `0x40000000` | return 0, read-back PASS | return 0, read-back PASS, target `0x4012d260` (`linOramCache`) |
| RADIX_ONLY `0x40000000` | return 0, read-back PASS | SIGILL (`-4`) |
| MAC27 `0x40000000` | return 0, read-back PASS | SIGILL (`-4`) |
| MAC27 `0x140000000` | return 0, read-back PASS | SIGILL (`-4`) |

The baseline log is:

```text
{"mode":"cd","status":0,"target":"0x4012d260","symbol":"linOramCache","word":512,"readback":"PASS","first":154}
```

The high-base control reports the same read-back with target `0x14014c000`.
The protected `cd` rows print only the loaded-page-permission line and then
terminate with SIGILL; no JSON result is produced.

## Attribution

Fresh debugger attribution for RADIX_ONLY, MAC27 and high-base MAC27:

```text
encbound_abort (code=3) at sdk/platform_layout.c:459
#1  encbound_require (...) at runtime/capability.c:186
#2  encbound_memcpy (dst=..., src=0x4014c000 <linOramCache>, n=512)
      at runtime/adapters.c:28
#3  opOneLinearScanBlock (structureId=0, index=0,
      block=0x4014c000 <linOramCache>, write=0)
      at prepared/enclave_data_structures.cpp:88
#4  sgx_opOneLinearScanBlock (...) at generated/Enclave_t.c:190
```

The high-base row is identical with `src=0x14014c000` and the corresponding
`0x140...` frames. `code=3` is `ENCBOUND_ERR_POLICY`, the expected rejection for
an unminted raw enclave pointer. The abort fires at the first unconditional
read at `:88`, before the 512-byte copy executes; the write at `:111` is
therefore never reached in the protected profiles. In BASELINE the target is
read and then overwritten; the second call reads the overwritten target and the
third returns the original pattern to the host.

## Functional regression

All four configurations still pass the existing functional host:

```text
{"result":"PASS","calls":1117,"byte_comparisons":336384,"reads":666,"writes":648,"structures":9,"tamper_recoveries":9}
```

The complete preset/ownership/closure/loaded-permission audits pass for the
47 application/library objects in each row, including the high-base image. The
nine GCM tamper-recovery cases remain separate SDK behaviour and are not
ENCBound protection results.

## Scope and limits

* SDK SIM plus SDK debugger attribution. No SGX hardware, timing, secret
  extraction, arbitrary-address sweep, unbounded write or code execution is
  claimed.
* The host knows the enclave base and the image symbol in SIM, as a loader
  does. This is a demonstration premise, not a production address leak.
* The target is one 512-byte application-global span; only BASELINE reaches the
  copies, and the control does not claim every enclave address is writable.
* The `[user_check]` host buffer in the functional workload remains host
  memory. The functional 1,117-ECALL matrix and its limits are unchanged.
* The full ObliDB SQL/ORAM surface, attestation/key-exchange closure, hardware,
  performance and complete application execution remain outside this result.

## Reproduction

```sh
python3 apps/oblidb/user_check.py --high-base --trace \
  --evidence evidence/2026-10-23-oblidb-user-check.json
```

Logs and the driver live under `build/oblidb/user-check/`; the four matched
builds live under `build/oblidb/all-compat-v1/`. The machine-readable record is
[2026-10-23-oblidb-user-check.json](2026-10-23-oblidb-user-check.json).

## Identities

* Pinned upstream `SabaEskandarian/ObliDB` at
  `6de5ba15eb27b4ddc86481e2eb8db549159344ea` (BSD-3-Clause).
* Upstream `isv_enclave/enclave_data_structures.cpp` SHA-256
  `3cb05eda0fa24a280656ce87adeab71b7fd56082f21ecc3ac8e63f57d5b71a6c`.
* Upstream `isv_enclave/isv_enclave.edl` SHA-256
  `31609243cef3a4f399fe6fd5e1a46c6abda5df1cc4e6769d20f66b0461abeeea`.
* Driver, build commands, per-row logs and attribution excerpts are bound in
  the JSON record.
