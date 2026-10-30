# Juliet: the twelve ENCBound admission failures resolved

The owner requested fixing twelve cases that compiled against the Intel SDK
but failed ENCBound admission: six `strncat` calls and six `snprintf` calls.
All twelve now compile and execute in the matched three-profile SDK SIM pilot.
Original Juliet bodies and requested lengths are unchanged. This extends the
[initial 117-case run](2026-10-11-juliet-pilot.md); it does not repair or bypass
the separate SDK header/library compatibility failures.

## Implementation and boundary

`runtime/adapters.c` adds checked `strncat` and a fixed-signature adapter for
exactly `snprintf(dst, n, "%s", src)`. The pass validates the new call ABIs,
requires an immutable literal format and one pointer argument, and redirects
the latter call before its general variadic rejection. Unsupported formatting
continues to fail compilation. BASELINE still calls the original SDK services.
The [contracts](../docs/legacy/contracts/library-adapters.md) specify full reads/writes,
null/zero behavior, arithmetic, returns, ownership and unsupported cases.

Both adapters establish source extents and validate the complete destination
write from its original capability before copying. `strncat` includes its
existing prefix and trailing NUL in the check. The formatting adapter preserves
truncation and the full would-have-written return length; zero capacity does
not touch destination. It checks only the bytes actually written, including
NUL, and visibly rejects results exceeding `INT_MAX`. No raw variadic formatter
receives a capability. Pointer mechanism, region policy and SDK backend are
unchanged. New code is local implementation, not an imported libc formatter.

## Fresh execution

Run directory:
[`build/juliet/pilot-2026-10-11-adapters/`](../build/juliet/pilot-2026-10-11-adapters/).
Archive pin, selection filter, SDK pins, application frontend/codegen O0,
trusted runtime O0, signed extent and fresh-enclave-per-variant procedure are
unchanged. All 286 extracted source hashes match the previous run. The 152
selected cases now produce **129 common builds and 774 execution rows**.

All **129 good variants return with matching output event counts and digests**
against BASELINE in each protected profile.

| Bad-case outcome | BASELINE | RADIX_ONLY | MAC27 |
| --- | ---: | ---: | ---: |
| Normal return | 76 | 45 | 21 |
| Attributed ENCBound rejection | 0 | 82 | 108 |
| Unattributed signal | 53 | 1 | 0 |
| Timeout | 0 | 1 | 0 |

For the **twelve new cases**, BASELINE has four returns and eight crashes.
Both protected profiles reject **all twelve**, each with RANGE code 4 at a
WRITE check in the appropriate library adapter. GDB traces retain the original
Juliet bad function, adapter, `encbound_require` arguments and terminal abort.

| Original operation / IDs | Checked write width | Destination slot |
| --- | ---: | ---: |
| `strncat`: 35, 41, 77, 83, 141, 162 | 100 | 64 |
| CWE805 `snprintf`: 37, 43, 143 | 100 | 64 |
| CWE806 `snprintf`: 79, 85, 164 | 99 | 64 |

Each destination capability has radix 6 and offset zero within its slot;
the original destination object is 50 bytes. The adapter abort occurs before
the append/format copy, at validation of its complete write. Native negative
controls independently check that destination contents remain unchanged on
these range failures. These twelve results demonstrate checked-library bounds
enforcement in **both** profiles; they add no new incremental MAC advantage.

All original 117 cases retain their outcome categories, abort codes and
enforcement classifications. Nine returning bad rows have different output
digests; these are retained, not treated as benign equivalence or silently
normalized. Every old good row's output is unchanged. The paired MAC advantage
remains the previous 26 additional TAG rejections; the previous 21 MAC returns,
RADIX_ONLY SIGSEGV and timeout remain. See the
[initial interpretation](2026-10-11-juliet-interpretation.md) for padding,
non-triggering inputs and rejections after intra-struct corruption. Neither
108/129 nor the other aggregate counts are an overall bug-prevention rate.

The remaining **23 compile failures occur in every profile**: fifteen report
undeclared `strcpy`, six undeclared `strcat`, and two report both `strcpy` and
`wcscpy`. The relevant SDK interfaces are hidden/deprecated or unavailable;
they have not been stubbed, exempted or admitted raw. This run does not prove
that repairing those SDK issues alone would establish their protected support.

## Validation and retained evidence

Commands, from the repository root (use a new pilot output directory to repeat):

```sh
make -C pass test > build/juliet/adapter-pass-tests.log 2>&1
make -C tests run > build/juliet/adapter-native-tests.log 2>&1
python3 tests/juliet/oracle_test.py > build/juliet/adapter-oracle-tests.log 2>&1
python3 tools/juliet.py --archive build/juliet/download/juliet-1.3.zip \
  --output build/juliet/pilot-2026-10-11-adapters
```

- Complete compiler suite passes. New coverage: 17 independently LLVM-valid
  IR controls in both profiles, plus four actual O0/O2 driver builds. Dynamic,
  mutable, `%n`, integer, wide, precision and prefixed formats; argument count,
  type, size, return and calling-convention mismatches; and unrelated variadic
  calls remain rejected. Accepted calls use only the checked symbols.
- Complete native suite passes. Library adapters: **115 checks MAC27 / 108
  RADIX_ONLY**, zero failures. Coverage includes libc comparison, truncation,
  zero capacity, interior/exact-fit buffers, unterminated strings, rejection
  before mutation, malformed format, forbidden raw enclave/trusted addresses
  and invalid MACs. Native tests use the fake platform and are not SGX results.
- Nine pilot oracle/section tests pass, including attribution for both new
  adapters. Every SIM profile passes SDK archive pins, constant-byte
  preservation, domain audit, signing and signed-layout verification.
- During test development, an invalid LLVM `fastcc` variadic negative fixture
  was replaced by a verifier-valid non-C ABI. A native fixture initially used
  an unmapped outside address as if runtime policy rejected all host ranges;
  it was corrected to a raw PROTECTED enclave address. The runtime's existing
  outside-range policy was preserved. Final suite logs above contain the
  passing runs; neither initial fixture failure was protection evidence.

The run retains source/IR/objects, binary hashes, SDK pin/audit/build logs,
individual process/debugger transcripts and implementation input snapshots.
[Summary](../build/juliet/pilot-2026-10-11-adapters/summary.json),
[rows](../build/juliet/pilot-2026-10-11-adapters/results.jsonl),
[selection](../build/juliet/pilot-2026-10-11-adapters/selection.json),
[identity](../build/juliet/pilot-2026-10-11-adapters/identity.json) and
[old/new comparison](../build/juliet/pilot-2026-10-11-adapters/adapter-comparison.json)
are the primary records. The comparison lists every changed old bad digest
and the 24 new protected rejection trace paths/widths.

| Artifact | SHA-256 |
| --- | --- |
| summary.json | `e2bed155bf01bf8bd0edc81b8734de8685ca1b7ff25e7dfb0cd3ba8ef1c9c405` |
| results.jsonl | `daf9abd061a4fba47dd9606ccf636fa19a765c614bc379cea03870d261fa3f59` |
| results.csv | `f8b9e70bb70f0e655a2c6a99c4f3c8e66404de5a33e3ea279bc4e1a9760a57ae` |
| selection.json | `f104d48c20199d2f851597a2b6922af897c37ab33218574e474ec706b29e8e41` |
| identity.json | `12e1436cb027bdc2ea732547b24e58f142ca15aa18b259edf50fa4876dbd236b` |
| adapter-comparison.json | `5a1d6b3fea27c143902ca69f2fee69522d85c6cfed1c3a90fc3e92ca8b24bb46` |

No SGX hardware, optimized Juliet, performance, general formatter coverage or
completion of the existing application/experiment gates is claimed.
