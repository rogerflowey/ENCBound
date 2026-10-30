# ObliDB selected linear-scan block workload

Pinned `SabaEskandarian/ObliDB` at
`6de5ba15eb27b4ddc86481e2eb8db549159344ea` (BSD-3-Clause, 2020-06-30).
This is a **bounded** recipe, not a full ObliDB SQL/ORAM integration.

The unchanged upstream `isv_enclave/enclave_data_structures.cpp`,
`definitions.cpp` and `definitions.h` are compiled with the `all-compat-v1`
preset. The selected original entries are:

```text
total_init
setupPerformanceTest
opOneLinearScanBlock
free_structure
```

`opOneLinearScanBlock` keeps its original signature, including
`[user_check]Linear_Scan_Block* block`. The recipe adds no EDL copy, range
contract or application validation for that pointer. The original
`printf`/`setupPerformanceTest` bodies are extracted byte for byte. The host
supplies the five original OCALLs with a bounded encrypted block store.

```sh
python3 apps/oblidb/user_check.py --trace
```

The functional host remains `host/host`; the user-check control uses the
separate `host/uc-host` and does not modify the selected ECALL, EDL or bridge.

## Functional matrix

Each row uses the full preset, frontend/codegen O2, protected writable globals,
one TCS, a 1 MiB SDK stack and the existing checked adapters for AES-GCM and
`sgx_read_rand`. The audit verifies source pins, object/IR/placement, library
membership, SDK archives, link/signature identity and ownership.

| Configuration | Result |
| --- | --- |
| BASELINE `0x40000000` | PASS: 1,117 ECALLs / 336,384 block-byte comparisons |
| RADIX_ONLY `0x40000000` | PASS: 1,117 / 336,384 |
| MAC27 `0x40000000` | PASS: 1,117 / 336,384 |
| MAC27 `0x140000000` | PASS: 1,117 / 336,384 |

The host creates nine structures, writes/reads blocks in forward and reverse
order, checks all 512 data bytes and guards, exercises session persistence and
recovers from nine deliberate AEAD tamper cases. Native adapter controls pass
168 checks in RADIX_ONLY and 192 in MAC27 at `-O0`/`-O2`; they validate complete
capability spans and the pre-call invalid-size/NULL paths against recording SDK
stand-ins.

## Direct `[user_check]` confused-deputy control

The untouched upstream body first reads 512 bytes from `block` unconditionally
(`prepared/enclave_data_structures.cpp:88`) and, on a read, writes 512 bytes
back (`:111`):

```text
public int opOneLinearScanBlock(int structureId, int index,
                                [user_check]Linear_Scan_Block* block, int write);
```

The `uc-host` `cd` mode names the image's own `linOramCache` global as `block`.
It stores a known pattern in block 0, asks the enclave to write block 0 to that
raw enclave address, then asks the enclave to read the same address into block 1
and returns block 1 through a normal host buffer. BASELINE recovers the pattern;
RADIX_ONLY, MAC27 and high-base MAC27 abort before the first 512-byte access.

| Configuration | `control` (host buffers) | `cd` (enclave address) |
| --- | --- | --- |
| BASELINE `0x40000000` | PASS, read-back PASS | PASS, target `0x4012d260` (`linOramCache`) |
| RADIX_ONLY `0x40000000` | PASS | SIGILL (`-4`) |
| MAC27 `0x40000000` | PASS | SIGILL (`-4`) |
| MAC27 `0x140000000` | PASS | SIGILL (`-4`) |

Fresh gdb attribution in all three protected rows:

```text
encbound_abort (code=3) at sdk/platform_layout.c:459
#1 encbound_require (...) at runtime/capability.c:186
#2 encbound_memcpy (..., src=0x4014c000 <linOramCache>, n=512)
      at runtime/adapters.c:28
#3 opOneLinearScanBlock (..., block=0x4014c000 <linOramCache>, write=0)
      at prepared/enclave_data_structures.cpp:88
```

`code=3` is `ENCBOUND_ERR_POLICY`; the access is rejected before the copy. The
high-base row is identical with `0x14014c000`.

The target is found in the image's `.symtab` and validated against
`/proc/self/maps`; no fixed scratch offset is assumed. This is SDK SIM only:
no SGX hardware, arbitrary-address sweep, secret extraction or unbounded write
is claimed. The host knows the enclave base and image symbol in SIM; that is a
demo premise, not a production address leak. The `[user_check]` host buffer in
the functional host remains host memory and is not protected.

## Reproduction and outputs

```sh
# Full four-row matrix with gdb attribution and machine evidence
python3 apps/oblidb/user_check.py --high-base --trace \
  --evidence evidence/2026-10-23-oblidb-user-check.json

# Reuse built images
python3 apps/oblidb/user_check.py --high-base --trace --skip-build
```

Build and run logs are under `build/oblidb/user-check/`; enclave/host artifacts
are under `build/oblidb/all-compat-v1/<profile>[/base<hex>]`. The machine record
is [the evidence JSON](../../evidence/2026-10-23-oblidb-user-check.json) and the
narrative is [the evidence record](../../evidence/2026-10-23-oblidb-user-check.md).

## Remaining scope

Only four of the original 44 ECALLs are selected. The original SQL surface
(`Condition` by value, anonymous `Schema`/block typedefs and the other
`[user_check]` arrays), the ORAM path, attestation/key-exchange closure, full
SQL execution, persistence, hardware and performance remain outside this
recipe. `user_check.py` is the only new control; no pointer mechanism,
protected scope, trusted boundary, backend or frozen target changed.

Origin/license: the build, library and audit scaffolding is adapted from this
project's `apps/conflow`; the user-check driver follows its existing direct
`[user_check]` control. The pinned ObliDB sources remain fetched build input
under their BSD-3-Clause licence. No upstream source is vendored.
