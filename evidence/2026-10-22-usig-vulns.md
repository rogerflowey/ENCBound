# USIG source vulnerability dig — 2026-10-22

Target: `ibalajiarun/go-consensus` at
`3a733ffd036a5b66d578f9002fca76ede40f8d47` (pinned by
[`apps/go-consensus-usig/pins.json`](../apps/go-consensus-usig/pins.json)).
Scope: the five ECALL bodies in
`enclaves/usig/enclave_usig/trusted/usig_enclave.cpp`. This record answers which
host-controlled memory-safety errors in the pinned USIG unit are reproducible.
It is **native AddressSanitizer on the unmodified application unit**, with local
SGX/Ed25519 stand-ins; it is not an SDK SIM, hardware, crypto or exploit result.

[Recipe](../apps/go-consensus-usig/vuln/README.md),
[machine-readable native record](2026-10-22-usig-vulns.json),
[release counter control](2026-10-22-usig-release-control.md) and
[init-overflow consequence control](2026-10-22-usig-key-replace.md) accompany
this record.

## Findings

| ID | Host input | Location | Native ASan |
| --- | --- | --- | --- |
| F1 | `mackey_len=1025` | `ecall_usig_init`, `strncpy(usig_mac_key, ...)` line 129 | `global-buffer-overflow`; `WRITE of size 1025`; 0 bytes after `usig_mac_key[1024]` |
| F2 | `_edd25519_sk_len=1024` | `ecall_usig_init`, original `edd25519_sk[edd25519_sk_len] = 0` line 134 | `global-buffer-overflow`; `WRITE of size 1`; 0 bytes after `edd25519_sk[1024]` |
| F3 | `_edd25519_sk_len=1060` | `ecall_usig_init`, `strncpy(edd25519_sk, ...)` line 132 | `global-buffer-overflow`; `WRITE of size 1060`; 0 bytes after `edd25519_sk[1024]` |
| F4 | `ctr_id=4`, three counters | `ecall_usig_create_ui_sig_edd25519`, `usig_counters[ctr_id]` line 264 | `heap-buffer-overflow`; `READ of size 8`; 8 bytes after the 24-byte vector allocation |

F1 and F3 are caller-sized copies into fixed global arrays. F2 is the
application's own one-past NUL store, not a checked libc copy. F4 is an
unchecked host-provided index: the loaded pointer is then used as the target of
`fetch_add`, so the release-mode impact is a heap OOB read followed by a write
attempt through an unauthenticated pointer.

The native build defines `-DNDEBUG`. The SGX libc++ port maps
`_LIBCPP_ASSERT` to C `assert` (`include/libcxx/__sgx`), so the default
integration build stops F4 with the existing `vector[]` assertion. That
assertion is a host-triggered abort (availability), not a spatial result. F4 is
the underlying spatial error when debug assertions are absent. F1/F2 already
have integrated SDK SIM controls; F4's release-mode control is separate.

## Reproduction

```sh
python3 apps/go-consensus-usig/vuln/run.py
python3 apps/go-consensus-usig/vuln/run.py --verify
```

The collector verifies the pinned source, compiles the unmodified application
unit with `-fsanitize=address`, runs the four adversarial cases plus a
`counter-in-range` control, and retains commands, log hashes and markers. The
stand-ins do not establish real crypto or SDK behavior.

## Record maintenance

The 2026-10-21 USIG integration record retains the application README as an
input. This additive 2026-10-22 section changed that file, so the retained hash
in [`2026-10-21-go-consensus-usig.json`](2026-10-21-go-consensus-usig.json) was
re-bound to the new README; its replay (`record.py --verify`) passes again with
2,064 hashes and the four closure audits. No 2026-10-21 result, artifact or
configuration was changed.

## Limits

* Native ASan only; the SDK bridge, trusted runtime and real crypto are outside
  this dig.
* ASan reports the first invalid access; no exploit, disclosure or control-flow
  consequence is claimed beyond the bounded release counter crash and the
  init-overflow key replacement recorded separately.
* F4's release build is a diagnostic configuration (`build_noassert.py`),
  not one of the four-row SDK SIM matrix configurations.
