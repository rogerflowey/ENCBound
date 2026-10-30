# Juliet first-pass pilot

See the [dedicated evaluation report](EVALUATION.md) for the latest
129-case protection results, their interpretation and runtime performance status.

This is the owner's October 11 request to set up Juliet and obtain rough results
before deciding how to reinterpret or rebenchmark. It supplements the existing
integration and evaluation work; it does not replace any selected application
workload or the authentication harness. Execution is **Intel SDK simulation**,
with the existing runtime, allocation geometry, stack mint/clear, compiler
admission and checks unchanged.

## Reproduce

Run from the repository root with the existing pinned SDK/source installation,
LLVM 21, GCC/binutils, Python 3, GDB, make and OpenSSL available:

```sh
mkdir -p build/juliet/download
curl -fL --retry 2 -o build/juliet/download/juliet-1.3.zip \
  https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
python3 tests/juliet/oracle_test.py
python3 tools/juliet.py --archive build/juliet/download/juliet-1.3.zip
```

The driver checks the archive hash before extracting anything. It accepts
`--sdk` / `SGX_SDK` and `--pinned` / `PINNED_SRC` for installation paths. Use
`--output <new-directory>` to name a fresh run; an existing directory is refused.
`--jobs 4` is the default; each process still has its own single-TCS enclave.
The default is frontend O0 and codegen O0. Optimized flags are selectable with
`--frontend=-O2 --codegen=-O2`, but this pilot establishes no optimized result.

Each completed output directory contains:

- `selection.json`: all candidates, source hashes, exclusions, per-profile
  compile outcomes and the common three-profile execution set.
- `summary.json`, `results.jsonl`, `results.csv`: raw outcome counts and rows.
- `source/`, `include/`: unchanged test bodies, original support headers and
  the explicitly adapted header copies.
- Per-profile `objects/`: input/checked IR, original and renamed ELF objects,
  build/rejection logs, undefined-symbol inventories and section-rename logs.
- Per-profile host, signed/unsigned enclave, linker map, generated bridges,
  signed metadata, SDK pin/audit logs, process and debugger transcripts.
- `identity.json` and `input-snapshot/`: tool/artifact hashes and copies of the
  implementation inputs used. Development signing keys stay in the local build.

## Selection and adaptations

The candidate inventory is **all 286 `_01.c` files** in CWE-121, 122, 124, 126
and 127 from Juliet C/C++ 1.3. Flow variant 01 avoids initially multiplying each
bug pattern by many control/data-flow templates. This is not the entire Juliet
suite or all C cases in those categories.

Before observing outcomes, the pilot excludes filenames containing `wchar_t`,
`socket`, `fgets`, `fscanf`, `rand` or `environment`. This leaves 152 candidates.
The filter is only a pilot selection rule, not proof of runtime compatibility;
for example, two `CWE135` cases also contain wide-character operations.
All selected cases are compiled separately in all three profiles. Only cases
that compile and pass object-domain/ownership checks in every profile enter the
matched execution set. A rejection is not counted as runtime protection.

The test bodies are byte-for-byte archive members. Their `INCLUDEMAIN` sections
are not enabled. A generated, instrumented switch calls either the original
`_good` or `_bad` entry, in a fresh enclave/process for each row. Both functions
remain in each case object; a rejected bad function excludes the whole case.

The support adaptations are explicit:

1. Remove unused `fcntl.h` and `sys/stat.h` umbrella includes from the support
   header copy; these POSIX headers are absent in SDK tlibc. Retain originals.
2. Spell `alloca` as the compiler builtin. Original lengths stay unchanged;
   unsupported dynamic allocations remain subject to compiler admission.
3. Map `exit(int)` to a terminal diagnostic scalar service in every profile.
   Exit requests are reported separately from ENCBound failures.
4. Replace the required `io.c` print functions with `support.c`. Every string
   character or struct field is read in instrumented application code before
   scalar values go to the trusted observer. The host records event count and
   an FNV-1a digest of those values; this is a comparison oracle, not a
   cryptographic commitment or preservation of printf's textual formatting.

The only application-admitted trusted services are `juliet_emit(kind,value)`
and `juliet_exit(status)`, both scalar-only. The SDK's internal OCALL imports
remain outside application admission. The trusted diagnostic ECALL initializes
the existing runtime before protected execution and refuses a second invocation.
BASELINE uses ordinary SDK pointers/allocation without ENCBound initialization.
There are no pointer-valued ECALL/OCALL arguments requiring capability bridges.

Only application-owned read-only sections enter the existing COMPAT range;
nonempty writable/TLS application sections fail this pilot's ownership audit.
The shared rename helper preserves section contents, and the pilot additionally
compares every renamed constant section's bytes with the original object.
SDK/runtime sections remain trusted. Existing libc wrappers handle admitted
memory/string operations; unavailable services are not stubbed or admitted raw.
The owner-authorized extension adds checked `strncat` and the exact
`snprintf(dst, n, "%s", src)` form used by twelve selected cases. The latter
lowers to a fixed-signature adapter; other variadic formats remain unsupported.
Arguments, source bodies and requested lengths are preserved. See the
[checked-adapter source](../../runtime/adapters.c) and
[extension results](../../evidence/2026-10-11-juliet-adapters.md).

## Reading the rough results

`returned` requires a zero host status, observed entry and completion, and a
matching case/variant return marker. It does not prove a bad operation executed.
Good-case output digests are compared with BASELINE separately.

A SIGILL alone stays `unattributed_signal`. In protected profiles, the driver
reruns it under GDB in a **fresh enclave with a fresh key**. Attribution requires
the terminal ENCBound abort, the selected good/bad case and ECALL frames, and
either the access-check arguments or the known checked `strncpy` adapter frame.
The latter's requested length is not labeled as an exact failing access width.
Raw execution and diagnostic rerun logs are both retained. Other signals and
timeouts remain visible and are never silently promoted to protection results.

The pilot does not establish all vulnerable-path reachability, exact source
object/slot geometry, unchanged target bytes for every rejected store, or an
overall bug-prevention rate. Padding/subobject and temporal limitations remain
as specified in DESIGN.md. Detailed reinterpretation and subsequent benchmark
selection follow the owner's review of these first results. There is no hardware
or performance result.

## Source and license

- Dataset: NSA Center for Assured Software, **Juliet C/C++ 1.3**, distributed by
  [NIST SARD suite 112](https://samate.nist.gov/SARD/test-suites/112?limit=50).
- Archive SHA-256:
  `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`.
- NIST states public-domain status in the United States and CC0 1.0 for foreign
  rights it may claim. The archive stays under `build/`; upstream comments and
  original header bytes are retained. No other dataset implementation is copied.
- The enclave Makefile follows this project's `sdk/Makefile`, whose SDK sample
  ancestry is Intel SGX SDK 2.26 SampleEnclave, BSD-3-Clause; see its provenance
  comments and the project's SOURCES.md. Existing platform/runtime code is reused
  directly and tested afresh, rather than importing the historical ENCBound tree.
