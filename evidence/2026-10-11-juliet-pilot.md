# Juliet 1.3 first-pass pilot — SDK simulation

This record preserves the initial 117-case result. The later owner-requested
[library adapter extension](2026-10-11-juliet-adapters.md) resolves twelve
admission failures and records a fresh 129-case / 774-row run.

The owner requested Juliet setup and rough results before deciding how to
reinterpret or rebenchmark. The pilot is implemented and has a fresh completed
**702-row SDK SIM run: 117 cases × good/bad × three profiles**. All 117 good
cases return in every profile, and both protected profiles match BASELINE's
output event counts/digests for all 117. No hardware, performance or general
bug-prevention-rate claim follows.

## Dataset and selection

[NIST SARD Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112?limit=50),
archive SHA-256:
`ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`.
The archive is verified before extraction; origin/license and every adaptation
are documented in [the pilot README](../tests/juliet/README.md).

- Candidate inventory: all **286** `_01.c` files in CWE-121, 122, 124, 126, 127.
- Predetermined pilot exclusions: **109** wide-character filenames and **25**
  external/random-input filenames. All remain in `selection.json` with reasons.
- Selected for build: **152**. BASELINE compiles 129; each protected profile
  compiles 117. The **117-case intersection** is the execution denominator.
- The other 35 selected cases fail visibly: 23 hit unavailable SDK declarations
  (`strcpy`, `strcat`, or `wcscpy` as the first error), six need unsupported
  `strncat`, and six need variadic `snprintf`. They are not protection successes.

Case bodies remain byte-identical to the archive. Support headers omit two
unused POSIX includes; a preinclude maps alloca to its builtin and exit to a
terminal diagnostic. Instrumented print helpers read application data before
forwarding scalar output observations. No unknown raw library call is admitted.

## Observed results

Bad variants only, denominator 117 per profile:

| Outcome | BASELINE | RADIX_ONLY | MAC27 |
| --- | ---: | ---: | ---: |
| Returned normally | 72 | 45 | 21 |
| Attributed ENCBound check rejection | 0 | 70 | 96 |
| Unattributed signal/crash | 45 | 1 | 0 |
| Timeout (15 seconds) | 0 | 1 | 0 |

Good variants: **117 returned and 117 matching outputs** in each protected
profile against BASELINE. The digest covers the print helpers' scalar event
stream, not upstream printf formatting, and is not a cryptographic oracle.

| CWE | Cases | RADIX_ONLY attributed rejections | MAC27 attributed rejections |
| --- | ---: | ---: | ---: |
| 121: stack overflow | 48 | 29 | 39 |
| 122: heap overflow | 30 | 17 | 22 |
| 124: underwrite | 13 | 10 | 13 |
| 126: overread | 13 | 6 | 9 |
| 127: underread | 13 | 8 | 13 |
| Total | 117 | 70 | 96 |

The 70 RADIX_ONLY rejections comprise 56 RANGE and 14 POLICY outcomes;
60 are through `encbound_require` at instrumented accesses and ten are in checked
library adapters. MAC27 has 56 RANGE, 28 TAG and 12 POLICY outcomes;
84 are instrumented-access checks and 12 are checked-library outcomes.
This is attribution to the observed checking site, not a claim that every stop
is at Juliet's originally labeled vulnerable operation.

The remaining RADIX_ONLY SIGSEGV is case 198,
`CWE124_Buffer_Underwrite__CWE839_negative_01`; its timeout is case 6,
`CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_01`. Both stay unresolved outcomes
for the next analysis. A normal bad-case return does not establish that its
vulnerable operation executed or that its source-level overflow is out of scope.

## Build, execution and evidence

- Intel SDK 2.26 SIM, debug enclave, one TCS, base `0x40000000`;
  signer-derived and verified extent, unchanged resource template.
- Clang/LLVM 21 pipeline; application frontend O0 and codegen O0 in every
  profile. Trusted sources use GCC O0 as in the diagnostic SDK build.
- Application cases, output helpers and dispatch are instrumented in protected
  builds; original/renamed objects and input/checked IR are retained. Runtime,
  SDK, generated scalar bridge and diagnostic observer remain trusted.
- App writable/TLS data fails this pilot's ownership check. Only each app
  object's read-only sections enter COMPAT; their bytes are checked before/after
  renaming. Trusted object markers and actual linked SDK archive pins are audited.
- Each variant runs in a new process/enclave. SIGILL cases rerun under GDB in
  another fresh instance/key. Attribution requires abort code, expected case and
  ECALL frames, and access-check arguments or the specific checked-strncpy frame.
  SIGILL alone, unrelated crashes, and application exit are not check results.

Final artifacts:
[`build/juliet/pilot-2026-10-11-final/`](../build/juliet/pilot-2026-10-11-final/).
Useful entry points are [summary.json](../build/juliet/pilot-2026-10-11-final/summary.json),
[results.csv](../build/juliet/pilot-2026-10-11-final/results.csv),
[results.jsonl](../build/juliet/pilot-2026-10-11-final/results.jsonl),
[selection.json](../build/juliet/pilot-2026-10-11-final/selection.json), and
[identity.json](../build/juliet/pilot-2026-10-11-final/identity.json).
These include per-row log paths, tool/input/artifact hashes, and input snapshots.

| File | SHA-256 |
| --- | --- |
| summary.json | `783c621dcf0b720367e5f3ca8cb5403527d44fd47bd9c5634951cbde4a468973` |
| results.jsonl | `2dcd53ade04f5b42b48d7d2e23d7153b7321be07cd5a3dbe6e71085f55e432e1` |
| results.csv | `2b5cc1c1a19431df6147e7368b8aff1a2e72503acb54ccecd4b5c1025ee17ea2` |
| selection.json | `8234c17a0748c712fd8216161a10a846534e92fde0c51d699f081bc7c1cfc7d3` |
| identity.json | `705db05bff88bfeadab08dbe4f67149a01ce1232a3e65c2eecd8d7e60b8098ae` |

Commands for the completed final run:

```sh
python3 tests/juliet/oracle_test.py
python3 tools/juliet.py --archive build/juliet/download/juliet-1.3.zip \
  --output build/juliet/pilot-2026-10-11-final
```

To reproduce, use a new output directory or omit `--output`. Nine oracle/helper
tests pass, covering misleading success markers/status, wrong-case/variant
attribution, unrelated crashes, adapter attribution, constant-byte preservation
and objects without read-only data. These tests also run via
`make -C tests evaluation-check` (the nine focused tests were run here).

## Correction discovered during setup

The pilot exposed an ordinary build error in the existing
`tools/mark_appdata_sections.sh` convention: renaming with flags
`alloc,load,readonly,data` but without `contents` zeroed the section payload on
the installed objcopy. The initial pilot copied this convention and produced
22 good-output mismatches. A retained probe under `build/juliet/section-probe/`
shows eleven-byte `AAAAAAAAAA\0` constants becoming zero without `contents`, and
remaining unchanged with it. The helper now includes `contents` and accepts
objects with zero read-only sections. The pilot verifies every renamed payload.
No protection check, pointer mechanism or region policy changed.

All earlier attempts remain under `build/juliet/`:

- `pilot-2026-10-11`: build stopped at missing SDK runtime OCALL imports;
  corrected by importing the pinned `sgx_tstdc.edl`, outside app admission.
- `pilot-2026-10-11-r2`: completed, but **invalid as protection evidence** because
  constants were corrupted. Its counts must not be used as results.
- `pilot-2026-10-11-r3`: fresh rebuild after byte-preservation correction;
  all 117 good outputs match. Its conservative oracle left four direct
  `encbound_strncpy` extent-check aborts unattributed. The final run adds tested
  adapter attribution and repeats all 702 rows in another fresh build directory.

Because the shared helper also serves LZ4, both existing diagnostic SDK profiles
were rebuilt and their LZ4 4096-byte round-trip/COMPAT probes rerun: **both pass**.
Logs are under `build/juliet/shared-helper-check/`; fresh probe records are
`build/evaluation-runs/lz4/SIM-MAC27-dbg1-0x40000000/20261011T073420-k3id6uuo/`
and `build/evaluation-runs/lz4/SIM-RADIX_ONLY-dbg1-0x40000000/20261011T073421-5b0amnph/`.
Old appdata-dependent evidence predates the fix; no old result is promoted to
the corrected binaries, and these reruns do not close LZ4 application acceptance.

## What remains for the next interpretation/rebenchmark decision

Keep these as rough outcomes. Establish which bad operations survived compilation
and executed, inspect exact requested/slot/access geometry, distinguish primary
bug prevention from later check failures, and explain returns, crashes and the
timeout. Padding, subobject, valid-capability reuse and temporal limits remain
unchanged; the short-tag guessing bound is not measured by this suite. Broader
flow variants, optimized builds and hardware are not evaluated here. The existing
two-application and experiment gates remain incomplete.
