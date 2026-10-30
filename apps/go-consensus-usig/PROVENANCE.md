# USIG source and license record

`pins.json` records repository `ibalajiarun/go-consensus`, revision
`3a733ffd036a5b66d578f9002fca76ede40f8d47`, the codeload archive SHA-256 and 29
selected input files. `prepare.py` extracts only those pinned paths, preserves
source comments/license headers and verifies them before each build.

The upstream root `LICENSE` is MIT, copyright 2022 Balaji Arun. The USIG source
also retains the Intel 2011–2020 BSD three-clause notice. Its bundled OpenBSD/
SUPERCOP Ed25519 files carry their original public-domain notices; the keypair
and verify-related sources remain in the selected full units even though the
USIG signing interface does not call those paths. Licenses remain in the
retained source tree; source bodies are not copied into this recipe.

The prepared-copy changes are exactly the symbol rename, SDK import and C API
linkage described in `README.md` and recorded with hashes in each `probe.json`.
The original seven application bodies remain unchanged except for the unused
`printf` name. No upstream bounds checks, allocator calls, key copying, counter
logic or debug calls are removed. The new public test harness uses test keys
from the upstream Go tests; generated local signing keys are for SIM only.

`crypto_support.c` supplies two missing application definitions.
`crypto_verify_32` is the public-domain Daniel J. Bernstein reference algorithm,
origin `nacl-20110221/crypto_verify/32/ref/verify.c`, as retained at
`apps/sk-sgx/upstream/verify.c` (OpenBSD revision 1.3). The repeated 32 byte
operations are written as a fixed loop and get new native equal/different-byte
tests. `randombytes` is a new SGX random-service wrapper with zero/error controls.
Neither is promoted into the trusted SDK domain.

The checked context-token pattern comes from this restart's
`apps/sgx-enclave-protocol/adapters.c` and close handling from
`apps/tpdv/adapters.c`. Build/audit/trace scaffolding follows the in-tree sk-sgx,
four-app and lifecycle recipes. The private Intel SDK libc++/tlibc components
retain their separate pinned origins and licenses in `apps/libcxx` and
`apps/libc-format`. The exact SDK crypto contract source and archive hashes are
included in the fresh evidence; no SDK crypto implementation is copied or edited.
