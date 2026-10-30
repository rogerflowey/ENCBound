# Selected SGX-KMS C16 session

From the artifact root with SGX_SDK and PINNED_SRC configured:

```sh
python3 tools/prepare-paper-sources.py --app sgx-kms
python3 apps/sgx-kms/test_adapters.py
python3 apps/sgx-kms/run.py --build build/sgx-kms/paper
python3 apps/sgx-kms/c16_protection.py --build build/sgx-kms/paper --trace
```

The original C16 body uses a shallow-copied void** slot after a valid current
RA/GCM session prefix. Independent host crypto checks the selected normal
outputs. Host-selected application/SDK enclave targets stop in the checked GCM
adapter before its key read. SDK-key use is a confinement observation, not
extraction of an unknown secret. The configured port excludes PSE/custom KDF;
full quote/IAS verification, deployment, cleanup/exhaustion, concurrency,
hardware and performance remain outside this bounded SDK SIM integration.
Source/license and port details are in PROVENANCE.md.
