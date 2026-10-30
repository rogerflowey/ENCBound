# USIG init-overflow key-replacement control — 2026-10-22

This control turns native finding **F1/F3** in
[the USIG vulnerability dig](2026-10-22-usig-vulns.md) into a bounded SDK SIM
consequence on the existing four USIG images. A hostile MAC key length is larger
than `usig_mac_key[1024]`; in BASELINE the excess bytes reach `edd25519_sk` and
replace the Ed25519 secret key. The original `edd25519_sk[edd25519_sk_len] = 0`
store then forces the seed's first byte to zero, so the source key's first byte
is nonzero and the public half matches the resulting seed. The source key has no
NUL, so `strncpy` does not pad or truncate the overflow.

```sh
python3 apps/go-consensus-usig/key_replace.py
python3 apps/go-consensus-usig/key_replace.py --verify
```

The control computes the `usig_mac_key` → `edd25519_sk` offset from the signed
image's symbol table, compiles a small host against the existing generated
bridge, calls `ecall_usig_init` with `_edd25519_sk_len=0`, then signs through the
original `ecall_usig_create_ui_sig_edd25519` and verifies the signature with
OpenSSL.

| Profile | Offset / length | Result |
| --- | --- | --- |
| BASELINE | 1,040 / 1,104 | `KEY-REPLACE PASS`: signature verifies with the attacker public key and fails with the legitimate public key |
| RADIX_ONLY | 2,048 / 2,112 | `SIGILL`: `encbound_abort(code=4)` in `encbound_strncpy`, `n=2112`, `usig_enclave.cpp:129` |
| MAC27 | 2,048 / 2,112 | same RANGE |
| MAC27-high | 2,048 / 2,112 | same RANGE |

Representative protected attribution:

```text
Program received signal SIGILL, Illegal instruction.
encbound_abort (code=4) at sdk/platform_layout.c:459
#1 encbound_require (...) at runtime/capability.c:186
#2 encbound_strncpy (... n=2112) at runtime/adapters.c:167
#3 ecall_usig_init (... _mackey_len=2112 ...) at .../usig_enclave.cpp:129
```

The machine-readable record is
[`2026-10-22-usig-key-replace.json`](2026-10-22-usig-key-replace.json).

## Limits

* The host in a real USIG deployment already supplies the key material at
  initialization, so this is a bounded state-corruption consequence, not a
  privilege escalation over the provisioning API.
* The protected offset differs from BASELINE because protected globals occupy
  separate slots; the control computes it per image.
* SDK SIM only; no hardware or exploit claim. The checked `strncpy` stops the
  write before any overflow reaches the key in the protected profiles.
