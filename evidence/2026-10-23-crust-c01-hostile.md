# C01 hostile two-call buffer-pool control — 2026-10-23

This record observes the hostile C01 sequence against the adapted selected
`crustio/crust-sworker` enclave. It adds the actual protection control that the
[selected incomplete-transfer integration](2026-10-23-crust-selected-integration.md)
left unexecuted. No compiler/runtime mechanism, EDL declaration, protected
scope, backend or evaluation target changed; the application body, allocation,
pool reuse and copy are the unchanged pinned source.

## Sequence

The selected public ECALL is `ecall_safe_store2`. Both calls use the same
`buffer_key` and incomplete-transfer type:

| Call | `total_size` | `partial_size` | `offset` | Result in the original body |
| --- | --- | --- | --- | --- |
| 1 | `0x100` | `1` | `0` | Allocates and retains one 256-byte pool buffer; `1 < 0x100`, so no completion. |
| 2 | `0x1000` | `0x400` | `0x800` | Reuses the 256-byte buffer; `memcpy(buffer + 0x800, data, 0x400)` is out of the slot. `0x800 + 0x400 < 0x1000`, so the restore callback is not reached. |

The 1,024-byte second input is the complete `partial_size` payload. The
sequence deliberately stops below `total_size`; the completing variant in
[DEMO-MATRIX](../research/nontrivial-ingress-bugs/DEMO-MATRIX.md) uses a
larger `partial_size`, enters the app-owned terminal restore stub and is a
different control.

## Fresh SDK SIM results

Four existing matched integration configurations were used:

| Configuration | First call | Second call | Attribution |
| --- | --- | --- | --- |
| BASELINE, `0x40000000` | `transport=0 app=0` | `transport=0 app=0`, process exit 0 | gdb at the raw `memcpy`: `n=1024`, caller `ecall_safe_store2`; destination bytes change from zeros to the payload |
| RADIX_ONLY, `0x40000000` | `transport=0 app=0` | SIGILL (exit 132) | `encbound_abort(code=4)` ← `encbound_require(width=1024, kind=2)` ← `encbound_memcpy(n=1024)` ← `ecall_safe_store2` |
| MAC27, `0x40000000` | `transport=0 app=0` | SIGILL (exit 132) | Same chain; rejected capability has radix 8 (256-byte slot), destination offset `0x1000900` |
| MAC27, `0x140000000` | `transport=0 app=0` | SIGILL (exit 132) | Same high-base chain at `0x140...` |

The [machine record](2026-10-23-crust-c01-hostile.json) retains the commands,
logs, image hashes and gdb excerpts. The BASELINE trace in that run observed the
second of the two n=1024 `memcpy` calls: the first is the generated bridge
copying the input, and the reported hit has `ecall_safe_store2` as its caller.

```text
application memcpy n=1024 dst=0x400378d0 src=0x40037220
0x400378d0: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0x40037220: 0x03 0x0a 0x11 0x18 0x1f 0x26 0x2d 0x34
#1 ... in ecall_safe_store2 ()
after application memcpy:
0x400378d0: 0x03 0x0a 0x11 0x18 0x1f 0x26 0x2d 0x34
```

The protected trace is the enforcing check on the exact second-call copy:

```text
#0 encbound_abort (code=4) at sdk/platform_layout.c:459
#1 encbound_require (capability=..., width=1024, kind=2)
       at runtime/capability.c:186
#2 encbound_memcpy (dst=..., src=..., n=1024)
       at runtime/adapters.c:27
#3 ecall_safe_store2 ()
```

`code=4` is `ENCBOUND_ERR_RANGE`. The destination capability has radix 8,
so its slot is 256 bytes; width 1,024 exceeds it. The low offset
`0x1000900` is the original first-call buffer at `0x1000100` advanced by
`0x800`. That identifies the same-key reuse rather than a new 4,096-byte
allocation. Both protected profiles stop before the write; BASELINE executes
the write and still returns success from both ECALLs.

## What this establishes

* The unchanged selected C01 body, with the recorded serial mutex and terminal
  restore adaptations, reaches the intended two-call stateful sequence in SDK
  simulation.
* BASELINE performs the out-of-slot 1,024-byte application write at
  `buffer+0x800`; gdb observes the destination change.
* RADIX_ONLY and MAC27 reject the same write at the checked destination range
  with `ENCBOUND_ERR_RANGE` (4), before memory is written, at both image bases.
* The completion callback is not involved: the hostile write is isolated from
  the terminal restore stub and the completed-transfer path.

## What this does not establish

* No SGX hardware, full storage-worker/HTTP/chain/IPFS deployment, real restore
  or completed-transfer cleanup result.
* The bounded 1,024-byte write is not an unbounded write gadget. Its later heap
  effects, a crash, secret reachability or exploitability are not characterized.
* C02 `spacex-storage` is a replication and was not built or run here.
* No repeated-session/resource-recovery, concurrency/reentrancy or performance
  claim. The selected scope remains serial, one TCS, with explicit no-op mutex
  stubs and the terminal restore callback.

## Reproduction

```sh
python3 apps/crust-selected/run.py                 # build the four images
python3 apps/crust-selected/hostile_control.py \
  --evidence evidence/2026-10-23-crust-c01-hostile.json
```

`hostile_control.py` compiles a separate driver against the existing images,
uses the same four configurations, checks the baseline statuses and protected
SIGILL outcomes, and runs the gdb attribution. `--build` runs the integration
matrix first; `--builds` and `--out` select other image/output directories.
Outputs default to `build/crust-selected/c01-hostile-v1/`.

## Identities

* Pinned upstream: `crustio/crust-sworker` revision
  `a109e0a60a4ea256d884fde192b06b025e8bd6b1`; selected body SHA-256
  `235991fbafed98c157c6b43c47707aac01149ce796b01b467821d6105c1c7603`.
* Images: the four `enclave.signed.so` files from
  `build/crust-selected/enclave-v1/all-compat-v1/`; per-image SHA-256, driver
  and gdb log hashes are in the machine record.
* The driver is local test code. The application, EDL, bridge, generated code
  and trusted runtime are unchanged by this control.
