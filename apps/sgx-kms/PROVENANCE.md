# SGX-KMS source and support provenance

Paper export: source files are fetched and checked using the same 67 file
hashes in `config/paper-sources.json`, under `build/paper-sources/sgx-kms`.
The runner no longer needs the sibling survey source collection. Historical
collection paths below identify the original provenance, not runtime inputs.

Application: [`cloud-security-research/sgx-kms`](https://github.com/cloud-security-research/sgx-kms),
revision `1c9d2d2df117845166196a1c3f6f2fb1b998e2c9`.
The runner verifies every file in the existing 67-file source manifest at
`../SGX-repo/analysis/2026-10-21-primary58-pointer-patterns/source-manifests/109753849.json`.
It reads that collection without changing it and copies the enclave sources
only into the requested build tree. The four enclave implementation files,
original EDL and headers carry Intel's 2011–2016 BSD-3-Clause notices, which
remain in the prepared copies. The host type header is extracted from the
pinned application's exact structure definitions and retains that notice.

The only application-source port replaces the removed PSE-session branch in
`enclave_init_ra`: `b_pse != 0` explicitly returns
`SGX_ERROR_FEATURE_NOT_SUPPORTED`; `0` uses standard `sgx_ra_init`. Custom key
derivation rejects at compile time. Exact before/after text, source hashes and
prepared hashes are recorded in `port.json` and `results.json`. The complete
`ecall_proc_ma` body is verified byte-identical to the upstream source and hashed.
All other application source/EDL/header bytes are copied unchanged.

`services.h` renames exact SDK service declarations/calls only for application
compilation. `adapters.c` is original ENCBound trusted support; its checked
range, staging and clearing patterns follow the existing SDK, sk-sgx, ObliDB
and RA-boundary adapters. No raw SDK names are admitted as application bodies.
`enclave.edl` imports the complete original EDL and adds the exact pinned
SDK-owned tstdc OCALL import needed by SDK/runtime code. The generated include
alias preserves the upstream `isv_enclave_t.h` spelling. It changes no public
application declaration.

The selected application formatter and errno provider are rebuilt through the
pass using [their existing source pins, licenses and configuration](../libc-format/PROVENANCE.md).
The 10 upstream formatter units, helper and common errno provider remain
application objects; they do not replace SDK libc. SDK libraries, original SDK
EDLs, generated bridges and runtime remain trusted with their existing exact
pins, including the optional RA archive/member contract. No SDK source or
installed library is modified.

The independent OpenSSL peer, loaded-page checks and build/signing methods adapt
original ENCBound code in `tests/sdk-ecalls` and `tests/early-bootstrap`.
The host links the installed OpenSSL library (`-lcrypto`); no OpenSSL source is
vendored and no `sample_libcrypto` binary or IAS behavior is substituted.
The remaining runner, audits, tests and documentation are original ENCBound
support. Native adapter tests use recording SDK spies and the existing fake
platform/real runtime; they supply no cryptographic or SGX result.

`c16_control_host.c`, `c16_protection.py` and `c16_layout.c` are original
ENCBound hostile-pointer controls over the same unchanged application body and
signed images. They reuse the independent OpenSSL RA peer and AES-GCM oracle.
The layout check reproduces the pinned SDK 2.26 private `ra_db_item_t` field
offsets; it does not modify or expose SDK state in the integration.
