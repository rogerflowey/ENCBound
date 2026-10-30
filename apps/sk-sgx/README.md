# mfriedl/sk-sgx: bounded integration and sealed-handle control

Pinned source: `mfriedl/sk-sgx` revision
`7368dfb3b95092e13c54191c93a79be668db24ef`. The complete non-debug trusted
closure is ten application units: `enclave`, `ed25519`, `fe25519`, `ge25519`,
`sc25519`, `sha256blocks`, `sha256hash`, `sha512blocks`, `sha512hash` and
`verify`. The original `sk.edl` exposes three ECALLs and the debug `ocall_puts`
declaration. The original `sk-sgx.c` provider is exercised by an independent
OpenSSL oracle; this is not a full OpenSSH client/server workflow.

[The evidence record](../../evidence/2026-10-21-sk-sgx.md) distinguishes the
native adapter tests, SDK SIM execution and the sealed-handle out-of-bounds
read control. No hardware, performance or general vulnerability-prevention
result is established.

## Configuration

New integrations use the [default preset](../../config/README.md), for example:

```sh
tools/with-integration-defaults.sh <command> [args...]
```

`probe.py` prepares the pinned source and the exact trusted adapter inventory.
The closure requires the scalar frontend (`-fno-vectorize
-fno-slp-vectorize`): the default vectorized frontend is rejected for
`fe25519` and `verify` because the pass does not admit
`llvm.vector.reduce.*`. The probe also applies one explicit source adaptation:
`malloc(aadlen)` becomes `malloc(aadlen ? aadlen : 1)` so the pinned empty-AAD
path preserves the SDK's zero-length behavior under the checked allocator. The
adaptation is recorded in `probe.json` and is identical in all configurations.

`adapters.c` maps the enclave's raw SDK services to checked trusted adapters:
`sgx_read_rand`, `sgx_calc_sealed_data_size`, `sgx_get_encrypt_txt_len`,
`sgx_get_add_mac_txt_len`, `sgx_seal_data`, `sgx_unseal_data`,
`consttime_memequal` and `memset_s`. The sealing adapters come from
`wrappers/sdk_adapters.c`; the sk-sgx-specific ones validate application
capabilities before the SDK routine sees a decoded address. There is no raw
application call to these services in the protected closure.

## Reproduction

The recorded build root is `build/sk-sgx/current-2026-10-21/`. It is already
populated, so a fresh reproduction should use a new root (for example
`build/sk-sgx/repro-2026-10-21`) and pass that root to `record.py`/`vuln.py`.
From the restart root, a fresh benign configuration is:

```sh
python3 apps/sk-sgx/probe.py --profile RADIX_ONLY --scalar \
  --out build/sk-sgx/current-2026-10-21/RADIX_ONLY
python3 apps/sk-sgx/finish.py \
  --build build/sk-sgx/current-2026-10-21/RADIX_ONLY --base 0x40000000
python3 apps/sk-sgx/trace.py \
  --build build/sk-sgx/current-2026-10-21/RADIX_ONLY
```

Use `--profile BASELINE` for the ordinary SDK configuration (no
instrumentation or protected adapters), `MAC27` for the complete protected
profile, and `--base 0x140000000` for the high-base MAC27 row. `finish.py`
links and signs the enclave, builds the independent host oracle and runs 68
ECALLs per configuration. The host checks the original error paths, bad
handles, wrong applications, repeated signatures, the provider path and fresh
OpenSSL verification.

Native adapter contracts (no SGX execution) are:

```sh
python3 apps/sk-sgx/native.py --out build/sk-sgx/current-2026-10-21/native
```

The default vectorized admission rejection is checked separately by running
`probe.py` into `build/sk-sgx/current-2026-10-21/vector-admission`; it must fail
for `fe25519` and `verify` with the unsupported-reduction diagnostic.

## Sealed-handle out-of-bounds read

The pinned enclave treats `key_handle` as `sgx_sealed_data_t` and calls
`sgx_get_encrypt_txt_len` at `enclave.c:178` and
`sgx_get_add_mac_txt_len` at `:189` before checking `key_handle_len` against a
required sealed size. The EDL copies exactly `key_handle_len` bytes
(`[in, size=key_handle_len]`), so a short handle makes those accessors read the
header past the trusted copy. For the pinned SDK 2.26 the real layout is
`sizeof(sgx_sealed_data_t) = 560`, `plain_text_offset` at byte 512 and
`aes_data.payload_size` at byte 528. The comments in the SDK header say 64 and
80; the compiled layout is authoritative.

The differential control is:

```sh
python3 apps/sk-sgx/vuln.py \
  --build-root build/sk-sgx/current-2026-10-21 \
  --output build/sk-sgx/current-2026-10-21/vuln.json
```

`vuln.py` does two independent things:

1. Builds `vuln_native.c` with AddressSanitizer against the unmodified
   `enclave.c` and the pinned SDK's real `tSeal_util.cpp`. `h1`
   (`key_handle_len = 1`) reports a 4-byte heap-buffer-overflow read in
   `sgx_get_encrypt_txt_len`, called from `enclave.c:178`. `h2`
   (`key_handle_len = 516`, `plain_text_offset = 64`) reports the read in
   `sgx_get_add_mac_txt_len`, called from `enclave.c:189`. The full-header `h0`
   control is rejected with `-1` and no report. Non-reached random/seal/unseal
   services are aborting stubs, not a substitute implementation.
2. Builds `vuln_host.c` for each recorded SDK SIM configuration and runs the
   same requests under GDB. BASELINE hardware read watchpoints fire at bytes
   512 and 528 of the real trusted copies, and the host returns `-1`.
   RADIX_ONLY, MAC27 and MAC27-high `h1` terminate with
   `encbound_abort(code=4)` in `encbound_sk_get_encrypt_txt_len`
   (`adapters.c:51`), called from `enclave.c:178` through the pinned trusted
   bridge. This is the RANGE rejection of the undersized capability. `h2`
   requests a 516-byte handle, which the allocator rounds to a 1024-byte slot;
   both accessor reads therefore stay inside that allocation, no spatial check
   fires, and the original `aadlen`/`key_handle_need` checks reject with `-1`.
   That in-slot uninitialized read is outside ENCBound's spatial-safety claim.

The control is a trusted checked-adapter rejection for one identified input,
not a compiler-inserted check at the original access and not an exploit or
information-disclosure result. The out-of-bounds value is not returned to the
host, and the sealing MAC still prevents use of a forged header. Lengths that
fit a rounded slot are not spatially rejected; uninitialized-memory safety and
the `SK_DEBUG` `%s` AAD-mismatch read remain outside this non-debug closure.

## Evidence collection

```sh
python3 apps/sk-sgx/record.py \
  --build-root build/sk-sgx/current-2026-10-21 \
  --output evidence/2026-10-21-sk-sgx.json
python3 apps/sk-sgx/record.py --verify evidence/2026-10-21-sk-sgx.json
python3 apps/sk-sgx/vuln.py --verify build/sk-sgx/current-2026-10-21/vuln.json
```

`record.py` requires four complete closure audits
(BASELINE/RADIX_ONLY/MAC27/MAC27-high), the native adapter rows, the expected
vector rejection and the sealed-handle record. The replay checks every retained
hash and repeats all four closure audits. Logs, signed images, objects and the
vulnerability control live under the recorded build root.
