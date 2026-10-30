# Application variadic callbacks

This fixture tests the existing explicit x86-64 SysV variadic frame through raw
application code pointers. It models SQLite's mutable heterogeneous syscall table:
functions are stored as `void (*)(void)`, cast back at the call, replaced and
restored across translation units. `ENCBOUND_VARIADICS=1` and
`ENCBOUND_CALLBACKS=1` are required; the integration preset supplies both.

Run from the repository root:

```sh
python3 tests/variadic-callbacks/run.py
```

`--native-only` runs the native/compiler/closure checks and is part of
`make -C pass test`. `--sim-only` runs the SDK configurations. Use `--build DIR`
for separate retained outputs. The default SDK/source paths follow the existing
[integration guide](../../docs/integration/APP_INTEGRATION.md).

Six native rows use all three profiles at matching frontend/backend O0 and O2;
the O2 rows link above 4 GiB. They execute on a real alternate machine stack with
the real runtime and a declared model of ELF regions. Each row compares 20 calls
against a separately compiled ordinary native-ABI oracle and the independent
expected bitmask 1023. Tests cover integer/pointer/double packing, both register
exhaustion paths, default promotions, zero unnamed arguments, recursion,
`va_copy`, fixed v-function forwarding, callback arguments, table replacement and
restoration, `fcntl`/`mremap` call shapes, pointer identity and an O2-inferred
`returned` parameter. Four native protected rows execute 18 terminal controls.

Four Intel SDK SIM configurations (BASELINE, RADIX_ONLY, MAC27 and high-base
MAC27) use actual generated bridges, protected globals, SDK linkage/signing,
ownership/ABI audits, metadata checks and loaded-page permission inspection.
Each runs 20 calls against the independent expected result. Fourteen protected
controls are attributed in GDB to `encbound_abort` reached from `va_bad` through
the indirect dispatcher: policy 3, range 4 or tag 5. The matched BASELINE private
write succeeds. Controls stop the application; test-only interception in native
children never resumes a failed access.

Compiler/verifier controls reject disabled callbacks, unowned variadic
declarations, unsupported operands/ABI attributes/conventions, operand bundles,
variadic aliases, invokes without EH mode and residual native variadic calls.
Three EH ABI-stage probes verify an indirect invoke retains its normal/unwind
edges and result; these are structural probes, not throwing callback execution.
Closure controls reject a missing or trusted callee, inconsistent flags/profile,
changed retained IR and native/wrong-profile links.

The new fixture code is original repository test code. The readers and corruption
cases reuse `tests/pass/variadics_readers.c`; `native.c` reduces the existing
`tests/errno/native.c` platform; signing/build flags reuse that fixture's recipe;
the loaded-page inspector is `tests/cxx-lifecycle/loaded_permissions.h`. The LLVM
transform retains its [pinned origin and license](../../pass/upstream/README.md).

No SGX hardware, performance, CFI, exact variadic argument-count/type safety,
native SDK variadic callback boundary or complete SQLite result is established.
Callers/targets must belong to the audited instrumented application closure and
use compatible source prototypes. Code-pointer integrity retains the existing
control-flow assumptions. Data pointers and frame storage retain ordinary checks.
