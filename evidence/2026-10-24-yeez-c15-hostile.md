# YeeZ C15 boundary-metadata controls — 2026-10-24

This record runs three C15 variants against the original YeeZ key-manager
ECALLs. The application, EDL, generated bridge, key-manager bodies and pinned
secp256k1 code are unchanged. The host calls the public ECALLs with hostile
size metadata:

| Variant | Public ECALL | Hostile size | Original unchecked write |
| --- | --- | --- | --- |
| `oversized` | `verify_signature` | `pkey_size=128` | `memcpy` into a fixed 64-byte stack `secp256k1_pubkey` |
| `generate` | `generate_ecc_key_pair` | `pkey_size=1` | 64-byte `memset`/public-key write into the 1-byte output |
| `sign` | `sign_message` | `sig_size=1` | 65-byte recoverable-signature output into the 1-byte output |

BASELINE performs the original write and later faults. RADIX_ONLY and MAC27
reject the checked write in two of the three variants. The `sign` variant is
reported separately because RADIX_ONLY does **not** reject it cleanly: the
original secp256k1 serializer performs 4-byte pointer-arithmetic stores across
16-byte protected slots, and RADIX_ONLY admits those cross-slot stores. MAC27
stops the first cross-slot store with `ENCBOUND_ERR_TAG` (5). This is consistent
with the documented slot-level model and with RADIX_ONLY omitting
authentication; it is not an exact-object-bound result.

## Results

Twelve SDK SIM rows: BASELINE, RADIX_ONLY, MAC27 and high-base MAC27; three
variants each.

| Configuration | Variant | Result | Attribution |
| --- | --- | --- | --- |
| BASELINE | `oversized` | unchecked copy, then SIGSEGV | application `memcpy(n=128)` copies `0x33` into a 64-byte stack object; later fault in `app_fmt___vfprintf` after the stack/control data are corrupted |
| BASELINE | `generate` | unchecked write, then SIGSEGV | `memset(pubkey,0,64)` into the 1-byte bridge allocation; later `free()` fault |
| BASELINE | `sign` | unchecked write, then SIGSEGV | recoverable-signature serializer writes 64 bytes into the 1-byte allocation (plus the 65th signature byte); later `free()` fault |
| RADIX_ONLY | `oversized` | SIGILL, code 4 | `encbound_require(width=128, kind=2)` -> `encbound_memcpy` <- `secp256k1::verify_signature`; before the copy |
| RADIX_ONLY | `generate` | SIGILL, code 4 | `encbound_require(width=64, kind=2)` -> `encbound_memset` <- `secp256k1_ec_pubkey_create`; before the write |
| RADIX_ONLY | `sign` | **survives** | capability `0x2000000001000020`, radix 4 (16-byte slot); the original 4-byte serializer stores cross slots and the host ECALL returns success |
| MAC27 | `oversized` | SIGILL, code 4 | same 128-byte write check as RADIX_ONLY |
| MAC27 | `generate` | SIGILL, code 4 | same 64-byte write check as RADIX_ONLY |
| MAC27 | `sign` | SIGILL, code 5 | tag mismatch at the first cross-slot store (`secp256k1_scalar_get_b32`); authentication, not a range result |
| MAC27 high | `oversized` | SIGILL, code 4 | same check at `0x180...` |
| MAC27 high | `generate` | SIGILL, code 4 | same check at `0x180...` |
| MAC27 high | `sign` | SIGILL, code 5 | same tag rejection at `0x180...` |

`code=4` is `ENCBOUND_ERR_RANGE`; `code=5` is `ENCBOUND_ERR_TAG`.

```text
# RADIX_ONLY oversized verify_signature
encbound_abort (code=4) <- encbound_require(width=128, kind=2)
  <- encbound_memcpy(dst=stack capability, src=..., n=128)
  <- ypc::crypto::secp256k1::verify_signature (... pkey_size=128)

# RADIX_ONLY/MAC27 generate_ecc_key_pair
encbound_abort (code=4) <- encbound_require(width=64, kind=2)
  <- encbound_memset(dst=..., c=0, n=64)
  <- secp256k1_ec_pubkey_create
  <- generate_ecc_key_pair (... pkey_size=1)

# MAC27 sign_message
encbound_abort (code=5) <- encbound_require(...)
  <- secp256k1_scalar_get_b32
  <- secp256k1_ecdsa_recoverable_signature_serialize_compact
  <- ypc::crypto::secp256k1::sign_message (... sig_size=65)
```

The RADIX_ONLY `sign` trace shows the write despite the successful ECALL:

```text
C15_CAP=0x2000000001000020 RADIX=4
C15_RAW=0x81000020
C15_AFTER_SERIALIZE
0x81000020: <64 signature bytes written across four 16-byte slots>
...
YEEZ C15 mode=sign status=0 ret=0 sig_size=1
YEEZ C15 SURVIVED mode=sign
```

## What this establishes

* The original key-manager ECALL bodies ignore the caller's smaller output
  sizes; BASELINE executes all three unchecked writes and later faults.
* RADIX_ONLY and MAC27 reject the oversized `verify_signature` stack copy with
  a checked 128-byte write at the 64-byte stack slot (range).
* RADIX_ONLY and MAC27 reject the 64-byte public-key write into the 1-byte
  output allocation with a checked 64-byte write (range).
* RADIX_ONLY does **not** stop the 65-byte signature write: the original
  library's 4-byte stores cross 16-byte slots and RADIX_ONLY admits them. MAC27
  stops the first cross-slot store with a tag failure. No exact-object bound is
  claimed for either profile.
* The high-base images show the same checks at `0x180000000`.

## What this does not establish

* The `sign` small-output variant is not a clean RADIX_ONLY protection result.
  It is recorded as a limitation of slot-level bounds and of the
  pointer-arithmetic store pattern in pinned secp256k1; MAC27's tag result is
  not a range-check result either.
* No secret extraction, signature forgery, key recovery, exploitability or
  adversary-controlled output beyond the bounded overwrites shown.
* No SGX hardware, full toolkit/deployment, timing or performance result. These
  are SDK SIM ECALL controls, separate from hardware.
* No claim that every C15 small-size path in the broader YeeZ API has the same
  behavior; only these three selected public ECALLs were run.

## Reproduction

```sh
python3 apps/yeez/c15_control.py \
  --out build/yeez/c15-hostile-v1 \
  --evidence evidence/2026-10-24-yeez-c15-hostile.json
```

`--config PROFILE-low|PROFILE-high --rebuild` selects one configuration. The
runner signs the audited unsigned key-manager images into
`build/yeez/c15-hostile-v1/` and runs the normal `host` binary built by
`apps/yeez/execute.py`; it does not overwrite the normal integration evidence.

## Identities

* Pinned upstream and recovered source as in the
  [C13/C14 record](2026-10-24-yeez-c13-c14-hostile.md): YeeZ
  `d6eadeca03d04848ea462ab2602f155219b6d3c3`.
* Key-manager unsigned SHA-256:
  * BASELINE `c6a6e021e8b8be571f27549e774dec2ea21fdf5feef9ed359e233bfe7209e7a2`
  * RADIX_ONLY `d205ea131df69fd96912b1cf1972d37eaad3afe6d6de7e970ce7d870b7c9eb30`
  * MAC27 `9f3e9449cc7db3b7a4ffe6829567cb0fb85fe392ba6584757047ea5aedf906d5`
* Per-row signed-image and host hashes, gdb scripts, logs and bytes dumps are in
  [`2026-10-24-yeez-c15-hostile.json`](2026-10-24-yeez-c15-hostile.json).
