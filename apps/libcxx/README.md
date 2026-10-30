# Instrumented Intel libc++ configuration

This builds pinned Intel SGX 2.26 libc++ as application code. Application template
instantiations and out-of-line library routines use the same capability ABI and
checks. The private `std::__encbound` namespace prevents resolution to the SDK's
raw-pointer C++ definitions. The SDK itself remains unchanged. The default is a
serial C++17 no-exceptions/no-RTTI configuration. A separate bounded exception/RTTI
configuration is described below; neither is complete standard-library support.

The starting probe attempts **all 39 upstream `.cpp` files**, without trimming
specializations. 36 compile to LLVM IR; `ios.cpp` and `sgx_mutex.cpp` require
exceptions, and `memory.cpp` hits a Clang constant-initialization diagnostic in
the SGX mutex pool. This is a full-source build attempt, not a successful full
library build. `probe_admission.py` records additional first-failure diagnostics;
its all-source declaration inventory is diagnostic only, never final admission.

`prepare.py` produces a reviewable local configuration with 25 source units,
including complete upstream narrow/wide `basic_string` explicit instantiations
and shared/weak control blocks. Many units are empty under the SDK configuration;
25 objects does **not** mean 25 facilities are supported. A new application unit
implements the required byte search and wide-character memory/string operations,
so the archive contains 26 objects. There is no container/type specialization
allowlist. A new application still needs a closed symbol/ABI/ownership inventory.

Exact adaptations and exclusions are recorded in `build/libcxx/sources.json`:

- `string.cpp`: omit standalone numeric conversions/formatting that require
  errno and varargs services in this selected configuration; retain both complete
  string template instantiations. The later common serial errno environment does
  not by itself restore or validate those omitted conversion functions.
- `memory.cpp`: omit exception-object definitions and the SGX mutex pool for
  atomic `shared_ptr` free functions; retain atomic reference counts, weak locking,
  virtual disposal and alignment helpers.
- Omit 14 whole units: `new` (existing allocation adapters supply its admitted
  operations), `ios`, `ios.instantiations`, `locale`, `strstream`, `sgx_mutex`,
  `sgx_condition_variable`, `random`, `stdexcept`, `system_error`, `any`, `optional`,
  `variant`, and `valarray`. The JSON gives each reason. Omitting exception
  implementation units does not prohibit all header-only uses of those types.
- Header overlay: retain the existing pinned Clang SGX configuration correction,
  select the private namespace, and route explicit compiler memory/search
  builtins to instrumented application implementations. Both compilation sides
  receive the same overlay and macro definitions.
- `utility`/`utility.cpp`: use C++17 inline `constexpr piecewise_construct`
  throughout the private closure and omit its duplicate out-of-line definition.
  This keeps one read-only ODR object; the SDK's external const class declaration
  otherwise lowers to mutable IR while its definition is read-only, producing a
  missing global capability cell under protected-global mode. The adaptation
  and all header/source hashes are recorded in `sources.json`.

Unknown services fail compiler admission or final symbol closure. Missing
facilities are not linked as trusted SDK C++ code. Terminal no-exception failure
adapters preserve termination; assertion diagnostic pointers are never read.
`ceilf` is an exact scalar-only trusted SDK math service for hash-table capacity.
These services live separately from the existing allocation adapters.

Application SGX mutex lock/unlock can now use the opt-in
[shared serial stubs](../serial-mutex/README.md): correctly stubbed for a recorded
serial/nonreentrant workload. This does not automatically include `sgx_mutex.cpp`
or complete `std::mutex` support in this library configuration.

From the repository root:

```sh
make -C pass
python3 apps/libcxx/probe.py
python3 apps/libcxx/probe_admission.py
python3 apps/libcxx/prepare.py
for profile in BASELINE RADIX_ONLY MAC27; do
  tools/with-integration-defaults.sh python3 apps/libcxx/build.py --profile "$profile"
done
python3 apps/libcxx/verify.py
```

`pins.json` freezes canonical SHA-256 manifests of the complete upstream tlibcxx
and SDK include trees. Preparation preserves upstream copyrights and stores
source/overlay hashes. Builds retain original and checked IR, dependencies,
compiler options, object hashes, and the archive hash. See [provenance](PROVENANCE.md)
and [the executable integration demonstration](../stl-service/README.md).

New integrations build this library and all callers with
`tools/with-integration-defaults.sh`. [Step 19](../../docs/legacy/steps/19-cxx-lifecycle.md)
adds bounded global/local-static lifecycle with trusted bootstrap/adapters; the
STL service's preset build exercises actual global/local-static strings/vectors.
Earlier results retain their original flags and adaptations.

Unsupported in the default configuration: exceptions/RTTI. Both configurations
exclude threading/TLS, pointer/floating/128-bit atomics, general
libc++ binary interoperability, and untested virtual-inheritance/member-pointer
forms. Atomics here do not authorize concurrent enclave execution. No hardware,
CFI, temporal-safety, general STL conformance or performance result is claimed.

For a different application, pass `--out-dir PATH`, repeated `--caller SOURCE`
and `--caller-flag=FLAG` options to `build.py`, under the integration preset.
The caller list supplies actual definitions for admission; it is not linked
into the library. Omitting the options retains the STL fixture's callers and
output paths. The mix/EnCloak recipes use isolated, fully rebuilt libraries; see
[their correction record](../../evidence/2026-10-20-four-app-integration-fixes.md).

With the new-integration preset's `ENCBOUND_APP_ERRNO=1`, the builder uses the
common application errno header environment during frontend probes and library
compilation. It inventories the actual common ABI definitions but does not
link a duplicate provider. The final application closure supplies instrumented,
placed `libc/errno.c` once; the selected formatter already includes it. Keep
caller flags/environment consistent and run the final ownership audit. See the
[errno recipe](../../libc/README.md).

With `ENCBOUND_CXX_EH=1`, `build.py` uses `-fexceptions -frtti` and selects 12
upstream units: algorithm, atomic, functional, hash, utility, vector, string,
stdexcept, optional, any, variant and the prepared `memory_eh` source. It adds
the existing application memory
helper and, in protected profiles, the new checked application type ABI. All
selected bodies, exception objects and throw helpers are instrumented. Use
`--frontend O0` or `O2`, an isolated `--out-dir`, and the same private headers and
macros for callers. The new mode retains `stdexcept`/optional/any/variant source
and licenses unchanged; the existing string adaptation remains.

The EH build now includes shared/weak control blocks and `bad_weak_ptr` bodies
from pinned `memory.cpp` through `memory_eh.cpp`. It keeps the existing explicit
exclusion of the mutex pool for atomic shared_ptr free functions. Nonpublic
control-block metadata follows the recompiled SDK RTTI behavior; it is no longer
rejected by an additional ENCBound semantic rule. Tests cover shared ownership,
weak locking/expiration, custom-deleter identity, disposal and recoverable
`bad_weak_ptr`. The no-exception source/configuration is unchanged. Threading,
locale/I/O, retained exception handles and other unselected services remain
unavailable. The full
[EH recipe and tests](../../tests/cxx-eh-rtti/README.md) exercise recoverable
vector/string/optional/any/variant/function/weak-pointer errors and standard exception bodies
under frontend/codegen O0/O2. SDK raw C++ fallback is rejected by the closure audit.
