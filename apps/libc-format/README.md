# Selected application libc formatting

This configuration recompiles `snprintf`, `vsnprintf` and their required source
closure through ENCBound. It builds **10 pinned tlibc C units, one application
memchr helper and the common application errno provider** (12 objects), using
the existing explicit variadic ABI. SDK/runtime libc remains
separate. [Provenance and licenses](PROVENANCE.md) identify every selected source.

```sh
make -C pass
make -C tools/edger8r
python3 apps/libc-format/run.py
python3 tests/integration/libc_format_test.py
python3 tests/integration/edger8r_admission_test.py
```

For new integrations run the builder/SDK runner under
`tools/with-integration-defaults.sh`. Use `run.py --build <directory>` to retain
a fresh isolated library and SDK matrix. The native fake-platform formatter
fixture uses its historical global mode and separately built libraries; its
`--library-root` and `--build` options isolate those artifacts.

The runner builds and audits BASELINE, RADIX_ONLY, MAC27 and MAC27 above 4 GiB,
then executes the same host oracle. Commands, hashes and results are in
`build/libc-format/sim-results.json`. Each row runs 244 formatting/error-recovery
calls and four Intel ECALL count-overflow rejections in one enclave; 80 calls
also exercise a capability-aware OCALL. Tests cover truncation/zero capacity,
register and overflow arguments, va_copy/forwarding, positional arguments,
dynamic width/precision, double conversion, wide text and explicit long-double
format errors. Outputs/return values compare against host libc. Loaded-image
page permissions, application ownership, complete definition closure, SDK pins
and BASELINE byte-for-byte stock bridge equality are checked separately.
Each SDK row also runs eight record ECALLs and eight record OCALLs, passing two
48-byte values plus a small record after six integer arguments. These check
register exhaustion, generated adapters, by-value isolation and repeated calls
across the C-host/C++-application boundary.

The October 20 OCALL user-check extension adds eight ECALL/OCALL pairs per row:
unused NULL/unmapped/noncanonical values, direct host string/pointer-array writes,
and opaque stack-capability round trips. That OCALL also takes an Options value
and an ordinary copied buffer, exercising generated record adapters and normal
copy-back alongside pass-through. The host never dereferences an enclave
capability. Native protection/error controls are recorded separately in
[the implementation evidence](../../evidence/2026-10-20-ocall-user-check.md).

The EDL includes a three-bool record passed by value from a C host into C++
application code, mutable input strings, typed `count`, literal `size`, bool
outputs and in/out buffers. Admission runs in native edger8r; Python coordinates
builds and evidence. Rejected shapes fail before bridge publication.

For a single profile, run `build.py --profile MAC27`, then
`make -C apps/libc-format PROFILE=MAC27`. Library outputs are under
`build/libc-format/MAC27`; `build.json` records sources, configuration changes,
flags, callable/data namespaces and hashes. `namespace.h` maps source libc names
to private `app_fmt_` names. The two common errno ABI symbols remain unchanged,
so all selected application libraries share one environment. The builder uses
`ENCBOUND_APP_ERRNO=1` for both probes and compilation and includes
`libc/errno.c`; do not link another provider. Compile every caller with that header, the stored
flags and `ENCBOUND_VARIADICS=1`, and include actual application definitions and
generated OCALLs in its inventory. The current builder's caller inventory names
this fixture's `service.cpp` and `dispatch.cpp`; another application must supply
its own actual definitions. Globals need application placement and final audits.
The WebAssemblyEnclave integration does so with `--out-dir`, repeated `--caller`
and `--caller-flag` arguments, and `--extra-pins` for its concrete additional
tlibc dependency set. These options do not change the default formatter fixture.
The extended selection retains private naming after upstream ctype `#undef`
directives; every additional definition still requires normal instrumentation,
placement and complete application ownership/dependency audits.
The archive contains application code; linking it as trusted SDK code is invalid.
Protected builds compile generated `enclave_app.c` through the same application
pass with `ENCBOUND_AGGREGATE_ABI=1`; the trusted `enclave_t.c` keeps its ordinary
SDK compilation. Both `admitted-app.txt` and `admitted-ocalls.txt` enter the
actual-definition inventory. New integrations using record values need the same
generated application object and application ownership checks. See the
[adapter implementation and evidence](../../evidence/2026-10-17-edl-value-record-adapters.md).

The closure uses existing checked memory/allocation adapters and the declared
terminal abort adapter. The `memchr` helper and common errno provider are
instrumented; errno/cache state is application-owned and serial. See the
[shared errno recipe](../../libc/README.md), including EDL propagation and SDK
state separation. Native tests run the actual formatter
on the real alternate application stack with the checked runtime: six execution
rows, 18 terminal protection controls and three raw-libc fallback link failures.
The SDK's deliberate `%n` abort is preserved and tested in six additional
terminal controls; those are not protection results.

Limits: no full-libc claim, stream/`printf` output service, application FILE/SDK
state sharing, TLS/threading, general locale, indirect variadics or long-double
variadic ABI. Long-double formats return `-1`; source long-double arguments still
fail compiler admission. The two pure numeric LLVM intrinsics needed by the
conversion code (`fabs`, `fmuladd`) are admitted without memory authority.
The tests establish native protection and SDK SIM functionality separately;
hardware execution, performance and full format-conformance remain unestablished.

When a caller also uses the private libc++ headers, use
`--caller-no-namespace` with its explicit selected-function macros (for example
`--caller-flag=-Dvsnprintf=app_fmt_vsnprintf`). This changes the caller inventory
probe only; all formatter definitions still use the complete private namespace.
The actual caller must use those same macros. See the
[mix/EnCloak recipe](../four_app_libraries.py).
