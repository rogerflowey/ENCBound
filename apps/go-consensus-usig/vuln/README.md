# USIG vulnerability dig (pinned source, native ASan)

Target: `ibalajiarun/go-consensus` at
`3a733ffd036a5b66d578f9002fca76ede40f8d47`, the same pinned revision as the
[USIG integration](../README.md). The relevant source is
`enclaves/usig/enclave_usig/trusted/usig_enclave.cpp`; the five ECALLs are
declared in `trusted/usig_enclave.edl`.

This directory **does not** integrate a new bug or change the enclave. It
reproduces reachable memory-safety errors in the unmodified source with native
AddressSanitizer: the five ECALL bodies are called directly with hostile
lengths/IDs, and SGX/Ed25519 services are local stand-ins. It is not an SDK SIM,
hardware or crypto result. The machine-readable record is
[`evidence/2026-10-22-usig-vulns.json`](../../../evidence/2026-10-22-usig-vulns.json).

## Findings

| ID | Input | Source | Native ASan |
| --- | --- | --- | --- |
| F1 | MAC key length 1,025 | `ecall_usig_init` line 129, `strncpy` into `usig_mac_key[1024]` | `global-buffer-overflow`, `WRITE of size 1025`, line 129 |
| F2 | Ed25519 key length 1,024 | `ecall_usig_init` line 134, original `edd25519_sk[edd25519_sk_len] = 0` | `global-buffer-overflow`, `WRITE of size 1`, line 134 |
| F3 | Ed25519 key length 1,060 | `ecall_usig_init` line 132, `strncpy` into `edd25519_sk[1024]` | `global-buffer-overflow`, `WRITE of size 1060`, line 132 |
| F4 | `ctr_id=4` with three counters | `ecall_usig_create_ui_sig_edd25519` line 264, unchecked `usig_counters[ctr_id]` | `heap-buffer-overflow`, `READ of size 8`, 8 bytes after the 24-byte vector allocation, line 264 |

F1/F3 are caller-sized copies into fixed globals. F2 is the application's own
one-past NUL store, not a library copy. F4 is an unchecked host-provided vector
index; the load is followed by `fetch_add` through the loaded pointer.

The native build uses `-DNDEBUG` because the SGX libc++ port maps
`_LIBCPP_ASSERT` to C `assert` (`include/libcxx/__sgx`), and the default
integration build stops F4 with the existing `vector[]` assertion. The default
assertion is a host-triggered enclave abort (DoS), not a spatial result. F4 is
the underlying release-mode spatial error.

## Reproduce

From the restart root, with the pinned SDK and Clang/LLVM 21:

```sh
python3 apps/go-consensus-usig/vuln/run.py
python3 apps/go-consensus-usig/vuln/run.py --verify
```

`run.py` calls `prepare()` (hash-pinned source), compiles
`trusted/usig_enclave.cpp` unmodified with `-fsanitize=address`, links the local
stand-ins, and runs the five cases. The expected terminal lines are:

```text
mackey-1025 ASAN 1
edkey-1024 ASAN 1
edkey-1060 ASAN 1
counter-oob ASAN 1
USIG VULN DIG PASS .../evidence/2026-10-22-usig-vulns.json
```

The JSON binds source pins, build commands, log hashes and the stable ASan
markers. `--verify` rechecks those hashes and markers; it does not rerun the
binaries.

## Scope and limits

* Native ASan on the unmodified application unit only; the SGX bridge, trusted
  runtime and real crypto are not part of this dig. The stand-ins do not
  establish crypto correctness or SDK behavior.
* F1/F2 already have integrated SDK SIM controls (the `key-overflow` and
  `ed-key-end` modes). F4's default integrated behavior is an assertion; its
  release-mode control is separate, in
  [`../release_control.py`](../release_control.py) and
  [`../../../evidence/2026-10-22-usig-release-control.md`](../../../evidence/2026-10-22-usig-release-control.md).
* The key-overflow consequence control is in
  [`../key_replace.py`](../key_replace.py) and
  [`../../../evidence/2026-10-22-usig-key-replace.md`](../../../evidence/2026-10-22-usig-key-replace.md).
* No exploit beyond ASan-attributed out-of-bounds accesses, a crash on the
  loaded counter pointer, and the bounded signing-key replacement is claimed.
  The host in a real USIG deployment already supplies key material at init;
  F4 is the stronger integrity/availability finding.
