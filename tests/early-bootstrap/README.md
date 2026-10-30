# Early trusted bootstrap probe

Run from the repository root:

```sh
python3 tests/early-bootstrap/run.py
python3 tests/early-bootstrap/attribute.py
```

The second command needs GDB and OS permission to trace its child processes.
Generated sources, objects, IR, signing configurations, images, logs and JSON
records stay in `build/integration/early-bootstrap/`. SDK paths can be selected
with `SGX_SDK` and `PINNED_SRC`; the existing SDK hash checks still apply.

The first command builds native ordering/failure controls, checks malformed and
misordered final initializer arrays, then builds BASELINE, RADIX_ONLY, MAC27 and
high-base MAC27 with the integration preset. Only the protected probe images
link `sdk/early_bootstrap.c`, before the trusted observer at the same priority.
No existing application recipe was changed by this bootstrap-only milestone.
The later [C5 work](../../evidence/2026-10-20-cxx-lifecycle.md) extends selected recipes.

The trusted observer runs ordinary instrumented C work from the SDK startup list
before the first ECALL bridge: checked stack/heap access, protected global access
and a static pointer fixup. Later ECALLs retain the exact keys/capability bits,
mutated pointer initializer and live heap allocation, allocate distinct temporary
objects, and free all application allocations. A startup OCALL attempts nested
entry, which the SDK must reject before a bridge runs. Final/loaded page checks,
global-slot ownership, application-call closure and pinned SDK archives are checked.
The initializer table itself remains denied to checked raw application accesses.

Separate injected SDK controls exercise runtime-initialization failure (STATE)
and a checked startup store across a heap-slot boundary (RANGE). `attribute.py`
records the abort category and enforcing call stack; a crash alone is not
protection evidence. The native controls use stubs and establish only bootstrap
ordering and terminal control flow.

This probe itself does not establish application constructor metadata, C++ destructor
registration, guards or COMDAT objects. A negative compiler control confirms
that application startup lists reject with lifecycle disabled. SDK SIM results do not establish
hardware execution, automatic destruction, general C++ lifecycle support or cost.

The build/link/sign and loaded-page inspection components are reduced from this
repository's `apps/pre-stl/Makefile` and `apps/pre-stl/host.c`; its pinned
`sgx_tstdc.edl` SDK-only import description is reused unchanged. Those components
derive from the Intel SDK sample structure recorded in `sdk/Makefile` and
`SOURCES.md` (Intel, BSD-3-Clause). Application/observer/control code is new.
