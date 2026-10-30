# Pinned Intel edger8r with native ENCBound admission

Origin/license hashes are in `upstream.json`; Intel BSD-3-Clause notices are
preserved in each copied OCaml source. `CodeGen.ml`, `Parser.mly` and
`Preprocessor.ml` are modified; `EncboundAdmission.ml` and `EncboundJson.ml` are
new; `sdk-ecalls.json` pins the optional SDK RA entry/provider contract. The upstream-to-current patch is `encbound.patch`. The SDK source is pinned by these
file hashes, not inferred from a sibling repository's git HEAD.

Build with `make -C tools/edger8r`. OCaml and ocamlbuild are required; no SDK
runtime rebuild is needed. Output is `build/edger8r/sgx_edger8r`. Without
`ENCBOUND_BRIDGE_CONFIG` it emits ordinary SDK code. `tools/modified_bridge.py`
is the admitted build entry point: it supplies configuration/compiler paths,
runs the native generator and compiles its emitted ABI assertions. Python never
parses or validates EDL and never rewrites generated C. The former Python parser
is retained only in the historical step-09 archive.

`EncboundAdmission.ml` validates Intel's parsed/preprocessed AST before emission,
derives application ECALL/OCALL selections, checks SDK import identities and
verifies scalar/value ABIs and shallow buffer transport types through Clang's AST. Native metadata,
the admitted OCALL list and C sizeof/align/offset/signature assertions are emitted
together. Real EDL preprocess/import/header dependencies enter the build manifest.
Ordinary integer/bool/float/double/enum values and arithmetic typedefs are always
enabled; `--wide-scalars` remains an accepted compatibility option. Shallow
typed in/out/inout buffers use Intel's length computation for literal or signed/
unsigned parameter extents, combined size/count and fixed multidimensional
arrays. Verified `isptr`/`isary` typedefs are admitted. Shallow byte copies may
contain pointer values and admit anonymous composites, flexible/zero-length tails,
unions, pointer arrays, `__int128`, complex types and other C element types without
field traversal. Complete types require C alignment at most 16; void/incomplete
types require explicit byte sizes and must not trigger generated `sizeof` use.
Char/wchar strings support both input and in/out, const or mutable as appropriate.
Value records use generated application adapters, including large records and
small records that Clang passes in memory after register exhaustion. The trusted
bridge exchanges explicit checked record pointers with these adapters; compile
`<stem>_app.c` through the application pass with `ENCBOUND_AGGREGATE_ABI=1` and
link it as application code. The original EDL, host API and application value
signatures remain intact. `admitted-app.txt` inventories generated application
definitions; `admitted-ocalls.txt` inventories the actual trusted gateway names.
Merge both with the application's actual-definition inventory. `<stem>_app.h`
declares the internal pointer interface. Pointer-free natural C layout remains
required; no 16-byte value-size limit is imposed.
ECALL and ordinary application OCALL `[user_check]` accept opaque data pointers,
multiple pointer levels and verified `isptr`/`isary` typedefs with no other
attributes. Data-pointer results preserve exact bits with an ABI assertion; their
later application access remains checked.
Intel transports pointer bits unchanged, without pointee access, decoding,
validation, copying, traversal or minting. Host memory supports direct access;
enclave capabilities remain opaque to the host. Ordinary copied buffers/result
destinations retain their checks, including calls with generated record adapters.
Admission and boundary manifests inventory `user_check_ecalls` and
`user_check_ocalls`; SDK-only imports remain separate. Intel `size`/`count` copying
remains shallow; EDL-requested deep-copy traversal is rejected. Value-record metadata
still names header-defined natural-layout struct typedefs; its existing exclusions
for enum fields, EDL-local values, unions, bitfields and custom alignment remain.
Deep-copy and by-value expansion are deferred. Intel's own parser restrictions
(including pure-output strings and arbitrary extent expressions) still apply.
See [step 17](../../docs/legacy/steps/17-edl-and-application-libc.md).

ECALL emission changes allocation, capability arguments and cleanup, and adds
shared initialize-once/session entry. OCALL emission checks/decodes application
pointers using Intel's computed `_len_` variables before marshaling. Strings get
a bounded char/wchar scan before Intel's strlen/wcslen and a direction/range check
against that same byte length. Imported SDK proxies remain ordinary raw code.
The generator emits no workload caps, exact-record-size rules, or app-status
output filtering. The trusted helpers are in `sdk/modified_bridge.h`.

Pinned SDK RA trusted imports have their own ECALL ownership selection. Only
the exact `sgx_tkey_exchange.edl` identity and declarations in `sdk-ecalls.json`
are admitted to this path. Application ECALLs use protected buffers; SDK ECALLs
use stock raw SDK buffers while acquiring/releasing the same serial-entry gate
in protected profiles. This works for SDK-only interfaces too. SDK entries do
not acquire application record or EH gateways, and do not enter application
definition inventories. Native/boundary manifests record `application_ecalls`,
`sdk_ecalls` and `sdk_ecall_imports`; `ecalls` retains all exported entries.
BASELINE without application errno propagation stays byte-identical to stock.
Preserve the SDK message-3 `user_check` pointer bits; the SDK validates its host
buffer. Raw application SDK calls still reject. Supply the generated boundary
manifest to the [final ownership audit](../audit_sdk_ecalls.py), which binds
definitions/private state to the pinned provider; EDL generation alone is
insufficient. See [the integration recipe](../../tests/sdk-ecalls/README.md).

Configured application OCALLs support `propagate_errno` in all three profiles.
Intel's host capture and guarded copy into SDK-private errno remain; after that
copy succeeds, the trusted proxy passes the copied integer to the instrumented
`__encbound_app_errno_store`. It does not expose an SDK pointer or reread the
host errno field. Unmarked OCALLs leave application errno unchanged; transport,
allocation and copy failures preserve its previous value. Link the
[common application provider](../../libc/README.md) once with the application
closure and use its application-only header environment. SDK-only imported
proxies remain SDK code. Both manifests record `propagate_errno_ocalls` and
`required_application_symbols`; the common ABI header is a recorded dependency.
The trusted bridge rejects compilation with the application errno overlay.
Configured BASELINE adds this same scalar handoff, so its trusted source differs
from stock only when application errno propagation is requested. Unconfigured
generation and configured BASELINE without marked application OCALLs keep stock
output equality. Serial/nonreentrant restrictions remain.

`python3 tests/modified_bridge_test.py` compiles and runs the actual emitted
bridges with native stubs in all three profiles, verifies stock output equality,
and exercises unsupported-shape rejection.
`tests/integration/edl_transport_admission_test.py` checks 38 transport fixtures in
all profiles against stock syntax and BASELINE output.
`tests/errno/run.py` supplies separate native runtime and SDK SIM propagation,
failure-ordering and private-state controls; see its [recipe](../../tests/errno/README.md).
`tests/integration/sdk_ecalls_test.py` checks SDK entry admission, stock equality,
EH exclusion and native transport-spy execution at O0/O2. The separate
`tests/sdk-ecalls/run.py` executes the actual pinned SDK RA implementation in SIM
against an independent OpenSSL peer and exercises final-link ownership failures.
`tests/integration/edl_shallow_test.py` adds six native O0/O2 rows with checked
application accesses through flexible/opaque/shallow buffers and pointer results.
`tests/integration/edger8r_admission_test.py` adds nested layouts, literal/count/
inout forms, real preprocessor dependencies and terminal OCALL extent controls.
`tests/integration/edl_buffers_test.py` executes separately instrumented application
code at O0/O2 in all profiles, testing arrays/typedefs/composites, shared extents,
char/wchar strings, failures/recovery and protection before raw access.
`tests/integration/edl_records_test.py` compiles the generated application side
separately and tests large/multiple/register-exhausted values at O0/O2, checked
record access, allocation/copy failures, cleanup and missing-adapter link failure.
`tests/integration/user_check_ocall_test.py` executes pointer-value transport,
direct host writes, opaque capability round trips, checked hostile results,
mixed-buffer/result guards and allocation/copy/transport error recovery.
[The libc formatter fixture](../../apps/libc-format/README.md) executes the new
forms with instrumented application code in matched SDK SIM profiles.
