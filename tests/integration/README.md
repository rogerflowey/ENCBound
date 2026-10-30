# Pre-STL validation

Run `python3 tests/integration/compiler_test.py`, `runtime_test.py`,
`globals_test.py`, and `wide_bridge_test.py` from the repository root.
The compiler tests use a synthetic capability decoder: they establish code
transformation semantics, not native SGX isolation. Runtime tests use the real
allocator/checker over the declared fake platform. The wider bridge tests
execute actual generated Intel C with native transport stubs.

The [variadic callback fixture](../variadic-callbacks/README.md) runs separate-unit
mutable function tables through the explicit variadic ABI. It includes a native
oracle with real runtime checks, actual SDK SIM configurations, attributed
protection controls and final application ABI/ownership audits. Its native suite
is included in `make -C pass test`; run `python3 tests/variadic-callbacks/run.py`
for the full native/SIM matrix.

`apps/pre-stl` separately builds and runs the real pinned SDK SIM component.
It covers upstream zlib callbacks, globals/RELRO, explicit aggregates, wider EDL,
and core C++ allocation/RAII. No STL implementation or application lifecycle is
included. Follow its README for build and source pins.

The libc++ follow-up adds `python3 tests/integration/atomic_runtime_test.py`:
checked 8/16/32/64-bit atomic IR executed against the real native runtime in both
protected profiles at O0/O2, with slot-crossing, stripped-capability and MAC-tag
failure controls. `tests/pass/atomic_virtual_test.py` also checks verifier
mutations, unsupported shapes, alias admission and assumption stripping.

`python3 tests/integration/user_check_ocall_test.py` executes emitted OCALL
proxies with separately instrumented application code on the modeled app stack.
It checks exact-bit pointer transport, direct host writes, opaque capability
round trips, hostile-result rejection, ordinary buffer/result guards and error
cleanup at O0/O2 in all three profiles. This is native fake-platform evidence;
the formatter fixture separately supplies matched SDK SIM/high-base execution.

`python3 tests/errno/run.py` checks the shared application errno environment and
generated `propagate_errno` handoff. Its [recipe](../errno/README.md) distinguishes
six real-runtime native model rows, four SDK SIM configurations, copy/transport
failure ordering, unique provider ownership and debugger-attributed SDK private
state controls. The selected formatter supplies separate regression coverage.

`python3 tests/integration/sdk_ecalls_test.py` checks pinned SDK RA ECALL imports,
mixed/SDK-only ownership, stock BASELINE equality, EH exclusion, selective
imports and negative admission. Twelve O0/O2 native rows execute actual emitted
bridges with transport spies, the real runtime, a synthetic platform and the
shared serial gate. They cover raw SDK buffers versus application capabilities,
nested refusal, initialization/terminal failure, cleanup and error recovery.
The spies do not implement RA. `python3 tests/sdk-ecalls/run.py` separately
executes the real SDK in SIM with an OpenSSL peer and final-link mutation
controls; see its [recipe and limits](../sdk-ecalls/README.md).
