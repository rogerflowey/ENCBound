# Selected YeeZ analyzer and key manager

Prepare sources with `python3 tools/prepare-paper-sources.py --app yeez`.
The exact app and fflib revisions, recovered file hashes and dependency unit
paths are retained in config/paper-sources.json and source-inputs.json.
No previous build-result JSON is a build input.

Build each profile with `python3 apps/yeez/run.py --profile PROFILE` and run it
with `python3 apps/yeez/execute.py --profile PROFILE`; add `--high` for MAC27's
high-base run. The root README gives the full matched matrix and native tests.
Run hostile_control.py and c15_control.py after that matrix.

This is the original selected first-match analyzer/default key-manager closure,
including raw, sealed and empty scenarios with independent crypto/output
checks. C13/C14 test hostile OCALL pointers; C15 tests host-controlled output
sizes. Small-output sign_message remains a RADIX_ONLY slot-granularity limit,
with MAC27 TAG rejection. Full toolkit, hardware, performance, general C++
conformance and universal vulnerability prevention are not established.
See PROVENANCE.md for source/license and trusted checked-service boundaries.
