# Origin and licensing

Upstream is the already-pinned Intel SGX SDK 2.26 source tree:
`/home/roger/project/TEE/ENCBound/.local/sgxbounds/intel-sgx-simulation-2.26/sdk/tlibcxx`.
The library's `LICENSE.TXT` and per-file SPDX/copyright notices are included in
the pinned tree manifest. LLVM libc++ files state Apache-2.0 WITH LLVM-exception;
Intel-specific files retain their own notices. No upstream source is vendored
into this directory. Preparation copies sources into ignored build output,
retaining notices, and records adaptations; it does not modify the source tree.

Headers come from the matching installed SDK 2.26 include tree. Both tree pins
are in `pins.json`, using SHA-256 over `json.dumps(relative_path_to_sha256,
sort_keys=True)` in Python. `sources.json` retains the individual source hashes,
configuration, exclusions and prepared-file hashes. The SDK binary archive pins
are independently checked by the existing `tools/check_sdk_pins.py`.

`wide_memory.cpp`, the preparation/build/probe/audit scripts, and the STL service
are new restart integration code. The STL service's host, EDL, linker/build and
layout-check scaffold derive from this repository's existing zlib service;
its container/virtual workload and Python oracles are new. No historical sibling
ENCBound implementation was copied.
