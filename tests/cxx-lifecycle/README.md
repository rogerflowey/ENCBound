# C++ lifecycle integration tests

Run from the repository root with pinned Clang/LLVM 21 and Intel SDK 2.26:

```sh
make -C tests cxx-lifecycle-check
python3 tests/cxx-lifecycle/run.py
python3 tests/cxx-lifecycle/audit.py
python3 tests/cxx-lifecycle/protection.py
python3 tests/cxx-lifecycle/protection.py --attribute
```

The last command needs GDB and OS permission to trace its child processes. Do not
count unexplained termination as protection. All outputs stay under
`build/integration/cxx-lifecycle/`; `SGX_SDK`/`PINNED_SRC` select matching pinned
SDK inputs for the SDK runner. Native controls currently use the recorded SDK
path explicitly. The original four SDK archives and the additional guard archive
are checked independently; historical four-archive closures remain unchanged.

`run.py` builds sixteen SDK SIM rows: BASELINE/RADIX_ONLY/MAC27 plus MAC27 above
4 GiB, frontend O0/O2 and both serial/default SDK guard code generation. Machine
code generation uses O2. Both application units consume the complete preset;
one is actually selected from an owned archive, with names/bytes/link-map
accounting. Trusted startup and lifecycle adapters remain ordinary trusted code.

Each row executes thirteen ECALLs. Prioritized dynamic globals and an array run
before the first bridge, allocate heap members and record order. Nontrivial local
statics run once; inline/template objects, guards and a writable pointer initializer
appear in both units to exercise COMDAT storage/cell/fixup selection. Repeated
calls retain state. Test-only trusted diagnostics invoke the actual SDK exit
registry twice, check reverse callback/array destruction order, run the actual SDK
finalizer-array routine and then allocate/free the entire 16 MiB protected arena
to establish reclamation/coalescence. Raw global storage, capability cells and
SDK DSO data remain denied to application accesses. Loaded permissions, ownership,
source/IR/placement provenance, startup order and SDK pins are checked.

`native.py` uses the real runtime with a synthetic platform and actual pinned SDK
guards. Four O0/O2 protected rows cover acquire/abort/retry/release, callback and
object bit preservation, actual SDK token forwarding, and unchanged registration
results including -1. Thirty attributed POLICY/RANGE/TAG controls ensure all
three guard adapters reject invalid storage before mutation. Only registration
transport uses a linker spy; it is not an SDK registry failure-injection result.

`admission.py` has 24 admission/output controls, including the independent
verifier. The October 21 USIG regression adds ordinary owned no-EH destructor
registration plus unknown, runtime-selected and wrong-ABI callback rejection.
Two malformed intrinsic-list forms are rejected by LLVM's own input verifier.
`audit.py` checks a real closure and lowercase ELF flags, then damages
cell/fixup groups and final selected cell count, and removes the bootstrap link
object. `protection.py` builds four SDK controls: a two-byte store from byte 15
of a 16-byte object in its constructor/destructor in each protected profile.
The attribution command requires RANGE code 4, `encbound_require` and the actual
constructor/destructor in the enforcing stack.

The full preset application regressions additionally rebuild all 26 configured
libc++ objects per profile, pre-STL and STL in four configurations. The STL
preset flags enable actual dynamic global/local-static string/vector state.
See [the evidence](../../evidence/2026-10-20-cxx-lifecycle.md) for exact commands,
build paths, recorded identities and results.

SDK SIM omits automatic destruction. Explicit test-only SDK draining establishes
callback behavior while runtime/stack state is valid; it does not add a production
shutdown endpoint or establish hardware teardown. No threads, exception recovery,
RTTI/TLS, CFI, temporal safety, general C++ conformance or cost result is claimed.

Build/link/sign scaffolding and the loaded-page helper are reduced from this
repository's early-bootstrap/pre-STL fixtures; the original SDK sample scaffolding
is Intel BSD-3-Clause, recorded in `SOURCES.md`. Fixture/application/control code
is new restart code. No SDK implementation source is copied: guard functions
link from pinned `libsgx_tcxx.a` (`sdk/cpprt/linux/guard.cc`, PathScale BSD-2-Clause)
and registration/dispatch from the original SDK runtime (`global_init.c`, Intel
BSD-3-Clause). Their notices remain in the pinned SDK source tree. The private
libc++ adaptation retains LLVM Apache-2.0 WITH LLVM-exception notices and its
own [provenance](../../apps/libcxx/PROVENANCE.md).
