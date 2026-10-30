# Default application integration configuration

Start every **new** C/C++ integration with [integration.env](integration.env).
It enables the established compatibility switches, full application data
placement and protected writable-global support. Bounded exceptions/RTTI add
the explicit closure-wide mode described below. Both protected profiles use
the same settings; BASELINE keeps ordinary pointers/globals and the matched
application variadic/C++ allocation configuration. Select the profile explicitly.

From the repository root:

```sh
mkdir -p build/my-app/MAC27
tools/with-integration-defaults.sh env ENCBOUND_PROFILE=MAC27 \
  ENCBOUND_ADMITTED="$PWD/build/my-app/MAC27/admitted.txt" \
  tools/encbound-cc.sh apps/my-app/worker.c build/my-app/MAC27/worker.o \
  -O2 -fno-common -fno-builtin
tools/with-integration-defaults.sh tools/mark_appdata_sections.sh \
  build/my-app/MAC27/worker.o build/my-app/MAC27/worker.placed.o
```

These are a template for your own source, output directory, frontend flags and
actual-definition inventory. Create the output directory first. Link the placed
object and retain its `.ownership.json` alongside the original compiler's
`.integration.json`, `.input.ll`, `.checked.ll` and dependency file. Placement
changes object bytes: preserve the compilation → placement → link hash chain.

The wrapper resolves the preset relative to itself and works from any directory;
arguments and exit status pass through unchanged. It applies fixed settings even
if the calling shell contains older feature values. To apply it to a whole build:

```sh
tools/with-integration-defaults.sh python3 apps/webassembly-enclave/run.py
```

Alternatively, source `. ./config/integration.env` in a build shell. For a new
GNU Make recipe, include it **before** local defaults, and make configuration
changes invalidate objects and linked artifacts:

```make
include $(ROOT)/config/integration.env
# Other source/header/compiler/plugin dependencies still apply.
$(APP_OBJECTS): $(ROOT)/config/integration.env
```

Use a fresh `build/<app>/all-compat-v1/<profile>/` tree for new integrations.
Library objects, generated application adapters and application callers must
all consume the same settings. Existing Make/Python recipes can assign their
own values after reading the environment: check `.integration.json` on **every**
object. The preset exports the existing Make aliases `PROTECTED_GLOBALS`,
`APP_CODEGEN_OPT`, `CHECK_REUSE`, `LOCAL_PROOFS` and `FAST_PATHS` as well. Explicit
Make command-line assignments still win; rebuild the entire closure when changing
any feature/ABI setting. The wrapper does not make an existing Makefile detect
environment changes or rebuild an existing library automatically.
Run existing feature-negative regression suites in their own recorded environment;
many deliberately leave switches unset to test rejection. Apply this preset to
application builds, including runners that build their dependencies.

| Setting | Preset value | Solved integration requirement |
| --- | --- | --- |
| `ENCBOUND_CALLBACKS` | `1` | Application function pointers and exact-signature checked service addresses |
| `ENCBOUND_AGGREGATE_ABI` | `1` | Application `byval`/`sret`, including generated EDL value adapters |
| `ENCBOUND_CXX_ALLOCATIONS` | `1` | Core new/delete, aligned allocation and admitted terminal/scalar services |
| `ENCBOUND_ATOMICS` | `1` | Checked 8/16/32/64-bit integer atomics |
| `ENCBOUND_VIRTUALS` | `1` | Admitted function aliases for virtual dispatch/destructors |
| `ENCBOUND_VARIADICS` | `1` | Direct/indirect application x86-64 integer/pointer/double variadics and va_list forwarding; stored function addresses and indirect calls also use the callback switch |
| `ENCBOUND_WRITABLE_GLOBALS` | `1` | Full object-owned RO/RELRO/RW/BSS placement |
| `ENCBOUND_PROTECTED_GLOBALS` | `1` | Individual writable-global slots, trusted capability table and initializer fixups |
| `ENCBOUND_CXX_LIFECYCLE` | `1` | SDK/compiler-preserving dynamic globals/local statics, ODR storage, destructor registration and checked guard services |
| `ENCBOUND_VLA` | `1` | Runtime-sized stack slots, checked sizing/capacity, private saves/restores and whole-slot clearing |
| `ENCBOUND_APP_ERRNO` | `1` | Application-only errno header environment shared across the closure; link the instrumented common provider once when used |
| `ENCBOUND_CODEGEN_OPT` | `-O2` | Tested machine-code generation; supply frontend `-O2` separately |
| Reuse / local proofs / fast paths | `off` / `0` / `off` | Initial integration configuration; performance experiments have separate gates |

`ENCBOUND_PROFILE`, `ENCBOUND_ADMITTED`, source pins, SDK paths, EDL metadata and
application/library frontend flags are workload inputs. Supply them explicitly.
The preset adds no service names or definition inventory entries. When errno is
used, include the two actual common provider definitions and link its application
object once, as described in [the errno recipe](../libc/README.md).

## Reuse the working library and bridge routes

Read [APP_INTEGRATION.md](../docs/integration/APP_INTEGRATION.md) before porting a build. Its
support matrix and acceptance procedure apply with the preset enabled.

| Requirement | Use the existing solution |
| --- | --- |
| Core C++ without STL | [encbound-cxx.sh](../tools/encbound-cxx.sh), which prepares the core headers; use it inside the preset wrapper |
| STL containers, strings, shared/weak ownership and virtual calls | [Instrumented libc++](../apps/libcxx/README.md) and [STL service](../apps/stl-service/README.md). Use the private `std::__encbound` overlay and exact `build.json` flags with `encbound-cc.sh`. The core C++ wrapper regenerates a different overlay. Rebuild the library under this preset too. |
| snprintf/vsnprintf | [Selected formatter](../apps/libc-format/README.md): private `namespace.h`, stored flags and an actual caller inventory. Compile both callers and definitions with the variadic ABI. |
| Application errno / EDL `propagate_errno` | [Shared serial errno](../libc/README.md): the preset supplies the application header overlay. Compile/place/link `libc/errno.c` once as application code; the formatter already provides it. Keep trusted/host compilation on ordinary SDK/system headers. Generated marked OCALLs hand off only a copied integer. |
| String/numeric/math/ctype/NaN dependencies | [WebAssemblyEnclave](../apps/webassembly-enclave/README.md): pinned extra-source closure passed to the formatter builder. Select the sources your workload needs. |
| EDL buffers, strings, signed lengths, size/count, scalar aliases | [Modified native Intel generator](../tools/edger8r/README.md) through `tools/modified_bridge.py`. These admitted forms are already enabled; `--wide-scalars` is unnecessary. |
| EDL record values, including large/register-exhausted records | Compile generated `<stem>_app.c` with the preset as application code; merge `admitted-app.txt` and `admitted-ocalls.txt` with actual definitions. `<stem>_t.c` remains trusted SDK code. |
| ECALL `[user_check]`, including `char **` | Existing generator preserves pointer bits. Application dereferences remain checked; no new copying/traversal adapter is needed. |
| OCALL `[user_check]`, including `char **` | Generator preserves pointer bits with the same known-type/sole-attribute rules. Host memory is accessed directly; enclave capabilities are opaque values on the host. Use copied buffers to export enclave contents. No compiler switch is needed. |
| Persistent mutable globals | The protected-globals startup handles cyclic/cross-unit writable pointer initializers once, preserving mutations across sequential calls. Retain placement and final ownership/permission audits. |
| YeeZ SDK RNG/GCM/CMAC/SHA and LAv1 initiator DH | [YeeZ recipe](../apps/yeez/README.md): application-only redirects plus exact adapter mappings; trusted SDK algorithms and staging stay private. The selected original first-match analyzer and default key manager now run raw/sealed/empty in four SDK SIM configurations; C13/C14 and two C15 variants are checked, with the C15 small-output `sign_message` slot-granularity limit recorded. Full toolkit/deployment and hardware remain separate. |
| Dynamic C++ globals/local statics | [Lifecycle evidence](../evidence/2026-10-20-cxx-lifecycle.md): keep SDK startup arrays and registry; link trusted early bootstrap first, checked lifecycle adapters and pinned SDK guard archive. The pre-STL/STL recipes implement this under the preset. |
| Application SGX mutex lock/unlock in selected serial workloads | [Shared serial mutex stubs](../apps/serial-mutex/README.md): correctly stubbed as an explicit application-only adaptation. Compile the shared source through the pass and apply its redirect only to selected application units in all profiles. Requires enforced serial/nonreentrant admission; SDK locks remain intact. This is opt-in, outside the preset. |

Both library builders accept `--out-dir`, repeated `--caller` and
`--caller-flag` arguments. Supply the actual caller sources and isolate each
application's outputs; omitting callers retains the historical demo inventory.
The [mix and EnCloak recipes](../apps/four_app_libraries.py) rebuild the complete
private closure and reject stale compiler inputs. When a caller combines libc++
with selected formatter functions, `--caller-no-namespace` omits the formatter's
complete namespace header during inventory collection; supply the same explicit
selected-symbol macros used by the actual application build. This avoids a
`memchr` macro collision with libc++ while keeping both libraries instrumented.
A raw SDK/library reference is not solved by adding its name to `admitted.txt`.

Protected globals reject immutable initializers needing writable-global
capabilities, non-ODR weak/custom-section storage, TLS and COMMON. With lifecycle
enabled, COMDAT Any `linkonce_odr`/`weak_odr` storage and validated startup lists
are admitted; storage, capability cells and fixups share the original selection.
Preserve RO/RELRO permissions and record a concrete failure. Do not switch back
to COMPAT silently to obtain a passing build. Application TLS/threads,
wider variadic ABIs, variadic function aliases and EDL-requested deep-copy
traversal remain unsupported. Application variadic callbacks have a
[tested closure-wide route](../tests/variadic-callbacks/README.md); native SDK/host
variadic callback boundaries remain unsupported. See the detailed support matrix before
classifying any of these as a new regression.

Bounded exceptions/RTTI use an additional, complete configuration:
`tools/with-integration-defaults.sh env ENCBOUND_CXX_EH=1 <command>`. Generate
bridges with `--cxx-eh`, pass their `eh-entries.txt` as
`ENCBOUND_CXX_EH_ENTRIES`, and rebuild every application/library unit. The
[working recipe](../tests/cxx-eh-rtti/README.md) supplies the application type ABI,
private trusted header adaptation, selected exception-enabled libc++ and mandatory
closure audit. Class graphs, including private/protected bases, repetitions and
shared virtual diamonds, follow the recompiled pinned SDK's RTTI behavior;
descriptor layouts, flags, virtual offsets and all memory checks remain validated. It
supports function/function-pointer type identity; function-pointer exception
matching remains excluded. The RTTI sources are rebuilt through the application
pass; see [source provenance](../apps/cxx-abi/README.md). This mode
terminates escaping ECALL/callback exceptions. Keep reuse/proofs/fast paths off.
The existing `all-compat-v1` preset retains its no-exception ABI by default;
historical builds and libraries are not silently converted to the new ABI.

The preset does not supply link objects automatically. A protected startup list
requires trusted `sdk/early_bootstrap.c` first in the final dynamic initializer
array, plus ordinary trusted `runtime/cxx_lifecycle.c`; link pinned
`libsgx_tcxx.a` for guard services in matched profiles. Run the final-image
bootstrap and complete ownership audits. BASELINE keeps ordinary SDK lifecycle.
SDK SIM does not automatically run destructors; explicit SDK callback draining
is a test diagnostic, not a required application shutdown API. See the
[fresh evidence and limits](../evidence/2026-10-20-cxx-lifecycle.md).

## Verify a new integration

1. Inspect every application/library manifest for all preset settings and matching
   profile, inventory, headers, private namespace and ABI. Keep SDK/runtime/bridge
   objects in their designated trusted build rules.
2. Run final object/definition/ownership audits and loaded RO/RELRO/RW permission
   checks. Check the entire application closure uses protected-global mode.
3. Run matched BASELINE, RADIX_ONLY and MAC27 workflows, plus high-base MAC27,
   with independent outputs and the required recovery/session cases.
4. Record native, SDK SIM and hardware evidence separately, and attribute any
   claimed protection rejection to its enforcing check. Update STATUS.md and
   a fresh evidence record.

Historical bare-driver/fixture defaults stay recorded with their original
evidence. The all-compat preset is the default entry point for new integrations;
its configuration is not a claim of arbitrary C/C++ support or hardware execution.
