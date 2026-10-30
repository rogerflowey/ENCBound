# VLA and dynamic-stack tests

From the repository root:

```sh
make -C tests vla-check
python3 tests/vla/run.py
python3 tests/vla/run.py --attribute
```

Use the pinned Clang/LLVM 21 and Intel SDK 2.26. SDK inputs can be selected with
`SGX_SDK` and `PINNED_SRC`. The last command needs GDB/process-tracing permission.
Outputs and commands are retained under `build/integration/vla/`.

`ENCBOUND_VLA=1` enables the compiler protocol; the new-integration preset sets
it for the full application/library closure. Bare-driver default remains zero.
The trusted helpers live in the existing `runtime/allocations.c` object.

| Suite | Evidence |
| --- | --- |
| `admission.py` | 24 valid LLVM input/output and driver rejection controls, including a missing frontend sizing phase; no object publication with the switch off |
| `protocol.py` | Four native runtime rows / 48 attributed controls; overflow, geometry, policy, exact headroom threshold and interior-slot clearing |
| `native.py` | Twelve frontend/codegen O0/O2 × three-profile rows on an actual alternate machine stack with the real runtime; 116 attributed terminal controls |
| `run.py` | Eight matched SDK SIM rows: two frontends × BASELINE/RADIX_ONLY/MAC27/high-base MAC27; six sequential ECALLs per row |
| `run.py --attribute` | Six SDK SIM debugger controls: ALLOC in sizing/capacity helpers and RANGE at the original checked store |

C fixtures exercise nested/over-aligned scopes, multidimensional arrays, builtin
alloca, early returns, break/continue and repeated lexical reclamation. A trusted
test-only observer validates full slot geometry/clearing before writes and dirties
padding for reuse. C++ fixtures exercise Clang's VLA extension with instrumented
constructors/destructors and trusted scalar observation of destructor count/value.
Observers are not application services or arbitrary production minting APIs.
SDK application units use the complete preset and retain placement, definition,
trusted/application ownership and pinned archive audits.

Signed-sizing regressions cover negative factors, direct/stored/nested/scaled
products, original 32-bit width and C++ VLA construction/destruction. Protected
negative controls include zero/negative extents, signed overflow, unsigned
overflow (including negative bit patterns) and scaled overflow. The driver runs
the value-only sizing phase before frontend optimization to retain signedness;
memory instrumentation stays late. The full matrix executes these regressions
with the unchanged checked runtime. See the
[correction record](../../evidence/2026-10-20-vla-signed-sizing-fix.md).

The 16 KiB headroom is spare capacity below a reservation, not application
storage. It is a conservative policy tested at its exact threshold; compiler
stack-usage artifacts record individual trusted helper frames. It is not a
whole-program bound for arbitrary callees/recursion. Direct allocation-size
products must not overflow; deliberately modular sizing is not promised by this
subset. Mixed/cyclic/deep/escaping stack tokens reject. Rounded-slot and temporal
limits remain; there is no hardware, performance, CFI or full C/C++ claim.

Fixture/observer code is new restart code. SDK build/sign scaffolding is reduced
from this repository's early-bootstrap/pre-STL fixtures, whose original Intel
BSD-3-Clause SDK sample provenance is recorded in `SOURCES.md`. LLVM's existing
PromoteMemToReg API is called rather than copying an implementation.
