# USIG release-mode counter control — 2026-10-22

This record is the SDK SIM counterpart to native finding **F4** in
[the USIG vulnerability dig](2026-10-22-usig-vulns.md): the pinned application
indexes `usig_counters[ctr_id]` with a host-provided ID and no explicit bounds
check. The default build's libc++ port maps `_LIBCPP_ASSERT` to C `assert`, so
the existing `bad-counter` control stops in `__assert` in every profile. That
is not a spatial result.

For this diagnostic only, `apps/go-consensus-usig/build.py` was given
`build_noassert.py`, an otherwise identical copy of `build.py` that adds
`-DNDEBUG` to the application units. The mechanism,
pointer format, protected scope, trusted boundary, SDK and images' base are
unchanged. The resulting builds are under
`build/go-consensus-usig/noassert-v1/`; they are **not** part of the four-row
SDK SIM matrix in [the integration record](2026-10-21-go-consensus-usig.md).

```sh
python3 apps/go-consensus-usig/build_noassert.py --profile BASELINE   --out build/go-consensus-usig/noassert-v1/BASELINE
python3 apps/go-consensus-usig/build_noassert.py --profile RADIX_ONLY --out build/go-consensus-usig/noassert-v1/RADIX_ONLY
python3 apps/go-consensus-usig/build_noassert.py --profile MAC27      --out build/go-consensus-usig/noassert-v1/MAC27
python3 apps/go-consensus-usig/release_control.py
python3 apps/go-consensus-usig/release_control.py --verify
```

Each build passes its normal 81-call oracle and the complete closure/ownership
audit before the control runs. The control calls the unchanged original ECALLs:
init with three counters, then `ecall_usig_create_ui_sig_edd25519` with
`ctr_id=4`.

| Profile | Direct result | Attributed stop |
| --- | --- | --- |
| BASELINE | `SIGSEGV` (139) | original line 264: OOB element load, then crash in `fetch_add` |
| RADIX_ONLY | `SIGSEGV` (139) | original line 264: rounded-slot load is not stopped by range alone; `fetch_add` crashes on the unauthenticated pointer |
| MAC27 | `SIGILL` (132) | `encbound_abort(code=5)` in `encbound_require` at line 264: tagged pointer rejection |

Representative protected attribution:

```text
Program received signal SIGILL, Illegal instruction.
encbound_abort (code=5) at sdk/platform_layout.c:459
#0 encbound_abort (code=5)
#1 encbound_require (...)
#2 ecall_usig_create_ui_sig_edd25519 (... ctr_id=4 ...) at .../usig_enclave.cpp:264
```

The default-build control remains the separate `__assert` / `__n < size()`
result in each `all-compat-v1/<profile>/controls/bad-counter-gdb.log`; the
release control reads and checks that contrast. The machine-readable record is
[`2026-10-22-usig-release-control.json`](2026-10-22-usig-release-control.json).

## Limits

* `-DNDEBUG` application units are a release diagnostic, not the default
  pinned build and not a frozen matrix configuration.
* RADIX_ONLY does not stop this particular rounded-slot element load; MAC27's
  tag check does. This is a MAC27-specific result, not a general RADIX_ONLY
  rejection.
* SDK SIM only; no hardware, exploit, disclosure or performance claim.
* Adding `-DNDEBUG` in `build_noassert.py` changes only the diagnostic build
  flag; no pointer
  mechanism, threat-model, protected-scope, backend or frozen-target change.
