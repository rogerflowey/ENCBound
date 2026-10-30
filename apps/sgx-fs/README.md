# Selected sgx-fs F2 control

```sh
python3 apps/sgx-fs/prepare.py
env -u SGX_SDK -u PINNED_SRC python3 apps/sgx-fs/run.py
env -u SGX_SDK -u PINNED_SRC python3 apps/sgx-fs/f2_control.py
```

prepare.py obtains its own pinned SDK/source/application under build/; it
extracts the SDK package without executing its installer. Inputs and outputs
must remain within the artifact tree. The four matched SDK SIM rows retain the
original 18-entry interface and functional checks. F2 reads 4096 bytes starting
4095 bytes into a 4096-byte block: BASELINE exposes adjacent harness-created
file plaintext; the protected profiles reject the checked copy's source extent
with RANGE. The original dated record is preserved under evidence/; new runs
write under build/evidence/. No FUSE deployment, production secret extraction,
hardware, full exploit, exact object bounds or performance result is claimed.
Application revision/hashes and license are in pins.json and LICENSE.upstream.
