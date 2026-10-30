# Source provenance

Pinned upstream: `mfriedl/sk-sgx@7368dfb3b95092e13c54191c93a79be668db24ef`. The small source closure in `upstream/` is retained unchanged; `pins.json` and `upstream/SHA256SUMS` record its file identities. Original per-file notices and the upstream README accompany the code. The pinned repository has no standalone LICENSE file; no new license is assigned by this export.

The integration compiles ten trusted application units with the matched scalar frontend and the recorded zero-length AAD allocation adaptation. The provider host, native SDK spies, checked adapters and scripts are local integration code. The public-domain Ed25519 implementation is also reused by the USIG port; see its origin/license record. Full OpenSSH deployment is outside the selected workflow.
