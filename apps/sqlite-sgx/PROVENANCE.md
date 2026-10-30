# Provenance

Paper export: fetch the original checkout inputs using
`tools/prepare-paper-sources.py --app sqlite-sgx`. `config/paper-sources.json`
retains the existing six source pins and additional consumed header/license
hashes verified from the same clean pinned checkout. The runner now prepares
its private libc++ sources before building, so a previous build is unnecessary.

The application inputs are read-only files from `yerzhan7/SGX_SQLite` revision
`c470f0a6afcbb2461a94faa6045df47450c3354b`; hashes are recorded in `pins.json`
and the dated evidence record. The selected Unix-VFS shim, host OCALL source,
`run.py`, the C03 host harness (`c03_host.c`, `c03_ocalls.c/h`) and the writable
`encbound_c03_canary` probe in `vfs_interface.c` are new ENCBound integration
code. The canary is the hostile target for the C03 control and is not used by
the normal SQLite path. The tlibc and libc++ source
closures are copied from the pinned Intel SGX simulation 2.26 source tree; their
upstream notices and hashes remain in the corresponding build manifests. No
upstream application checkout is modified.
