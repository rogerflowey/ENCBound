# YeeZ integration sources and reuse

Paper export: `config/paper-sources.json` preserves the exact recovered source
and archive hashes; `tools/prepare-paper-sources.py --app yeez` reconstructs them
under `build/paper-sources/yeez`. `source-inputs.json` replaces dependency path
lookups in historical build results. `integer_to_string.cpp` retains the exact
previously selected SDK libc++ integer conversion bytes and LLVM notice; its
license is in `LICENSE.LLVM`. Application and trusted implementation bodies are
unchanged. Old assessment paths below describe original provenance.

The adapters, redirect declarations, build/evidence scripts and service fixtures
in this directory are original ENCBound integration support. RNG, AES-GCM, CMAC
and secure-memset checks reuse the understood patterns in this repository's
`apps/sgx-kms/adapters.c`; that file and its behavior are unchanged. Its native
adapter regression passes separately. The simulation build/sign/ownership
recipe follows `tests/sdk-ecalls/run.py`; loaded-page inspection reuses
`tests/cxx-lifecycle/loaded_permissions.h`.

The crypto and DH algorithms are the existing pinned Intel SGX SDK 2.26 archive
implementations. No crypto implementation is copied or rewritten here. The
public `sgx_dh.h` declares the caller-owned 200-byte session; the reviewed
`sdk/ec_dh_lib/sgx_dh_internal.h` layout contains no pointers/handles, and
`sdk/ec_dh_lib/ec_dh.cpp` defines message extents, state writes and return-code
conversion. Original Intel notices remain in the SDK source tree. Archive pins,
SDK/header dependencies and inspected-source hashes are retained in the build
manifests and dated evidence JSON.

The retained dependency inputs are YeeZ
`d6eadeca03d04848ea462ab2602f155219b6d3c3` and its fflib gitlink
`313273a3c744c539b712256f281ec1dd8ae376a1`, recovered and hash-checked by the
earlier [assessment](../../evidence/2026-10-23-yeez-blockers.md). All 688 YeeZ
files and 143 fflib files retain their embedded notices; fflib's MIT license
remains in the recovered tree. YeeZ has no repository-wide LICENSE/COPYING at
this pin. Upstream source stays under `build/`, with no redistribution into
this directory and no application/EDL body edits.

Private libc++ sources retain their Apache-2.0 WITH LLVM-exception notices.
The selected secp256k1 source retains its MIT notice. Their previous preparation,
RTTI reuse and selected formatter adaptations remain separately recorded; the
new service header changes application call routing only.

Known-answer fixture constants are the SHA-256 digest of `abc`, the NIST
SP 800-38B AES-CMAC empty-message example with key
`2b7e151628aed2a6abf7158809cf4f3c`, and the AES-GCM all-zero 128-bit key,
96-bit IV and 128-bit plaintext example (ciphertext `0388dace60b6a392f328c2b971b2fe78`,
tag `ab6e47d42cec13bdf53a67b21257bddf`). The DH fixture uses the actual SDK
responder and initiator, so it establishes SDK key agreement and error handling,
not an independent cryptographic proof or hardware attestation.
