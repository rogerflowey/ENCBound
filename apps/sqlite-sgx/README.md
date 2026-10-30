# Selected SGX_SQLite Unix-VFS route

```sh
python3 tools/prepare-paper-sources.py --app sqlite-sgx
tools/with-integration-defaults.sh python3 apps/sqlite-sgx/run.py
```

The runner prepares its private library, builds/audits the matched four SDK SIM
rows, and runs normal and C03 hostile workflows. The explicit serial Unix-VFS
adaptation disables WAL/mmap and uses typed filesystem/time OCALLs. C03 caches
a host-provided protected canary pointer from getenv and later uses it as an
OCALL string in two close/reopen phases. BASELINE discloses it; protected
profiles reject in encbound_bridge_string. This is boundary-service enforcement.
COMPAT read-only targets remain admitted. Normal host TMPDIR/SQLITE_TMPDIR
values are also rejected by that protected bridge; benign runs leave them unset
and use /var/tmp. No full POSIX/SQLite, concurrency, hardware or performance
result is implied. See PROVENANCE.md and the selected original C03 record.
