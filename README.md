# ENCBound

ENCBound is a research prototype for memory protection inside Intel SGX
enclaves. SGX isolates an enclave from its host, but memory bugs in enclave
application code can still reach other enclave data. ENCBound checks application
and library memory accesses to limit that risk, including accesses through
corrupted pointers or pointers supplied by an untrusted host.

The design combines LLVM instrumentation, power-of-two allocation slots and
keyed pointer tags. Checks protect application heap and stack slots, plus
writable-global slots when enabled. The SDK, bridge, runtime and checked
adapters remain trusted.

Three matched configurations support evaluation:

- **BASELINE** — ordinary SGX SDK pointers and allocation.
- **RADIX_ONLY** — slot and region checks without pointer authentication.
- **MAC27** — the same checks with a 27-bit keyed pointer tag.

The repository includes the compiler pass and runtime,
[13 bounded application integrations](apps/README.md), a
[selected Juliet C test suite](tests/juliet/EVALUATION.md),
[five benchmark kernels](apps/general-bench/README.md) and
[recorded validation](VALIDATION.json).

## Getting started

Use Linux x86-64, Clang/LLVM 21 and Intel SGX SDK 2.26. See the
[build and reproduction guide](BUILDING.md) for pinned dependencies, build
commands and workload recipes, and the [integration configuration](config/README.md)
for application settings.

Current results cover native tests and SDK simulation; SGX hardware results
are not established. Protection assumes admitted code and trusted call paths.
Bounds cover rounded slots; exact object bounds, temporal safety and
control-flow integrity are outside scope. The build guide details the
[assumptions and limitations](BUILDING.md#protection-scope).
