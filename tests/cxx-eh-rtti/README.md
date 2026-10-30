# Bounded C++ exception and RTTI integration

Enable `ENCBOUND_CXX_EH=1` **across the whole application/library closure**, on top
of [the integration preset](../../config/README.md). `encbound-cxx.sh` selects
`-fexceptions -frtti` in this mode; direct `encbound-cc.sh` calls must pass them.
The existing all-compat-v1 no-exception configuration remains available.

Generate bridges with `tools/modified_bridge.py --cxx-eh`. Pass its emitted
`eh-entries.txt` as `ENCBOUND_CXX_EH_ENTRIES` when compiling application units.
The compiler preserves original functions/internal calls and generates separate
terminating ECALL, startup and destructor wrappers. Generated bridges call these
wrappers, so an escaping exception cannot bypass bridge cleanup.

Protected builds compile [typeinfo.cpp](../../apps/cxx-abi/typeinfo.cpp) as
application code, with actual definitions included in the admission inventory.
Link [runtime.cpp](../../runtime/cxx_eh/runtime.cpp) as trusted code using the
pinned headers produced by `runtime/cxx_eh/prepare.py`, plus the ordinary checked
runtime, allocation, C++ services and lifecycle adapters. Keep the pinned SDK
`libsgx_tcxx.a` unwinder. BASELINE uses the ordinary SDK C++ ABI and the same
terminating entry policy. See `run.py` for an executable complete recipe.

For libc++, set the same flag when running `apps/libcxx/build.py`; use the private
header overlay/macros in its `build.json` for every caller. This selects 12
upstream units (algorithm, atomic, functional, hash, utility, vector, string,
stdexcept, optional, any, variant and prepared `memory_eh`), the existing
application memory helper and, in protected builds, the checked type ABI:
13 BASELINE / 14 protected objects. Shared/weak control blocks and `bad_weak_ptr`
are included. Mutex-backed atomic shared_ptr free functions, threading,
I/O/locale, retained exception handles and other unselected library services
remain outside this EH configuration. Missing symbols/unsupported metadata
fail visibly.

From the repository root:

```sh
python3 tests/cxx-eh-rtti/run.py
python3 tests/cxx-eh-rtti/run.py --codegen O0
python3 tests/cxx-eh-rtti/run.py --libcxx
python3 tests/cxx-eh-rtti/run.py --libcxx --codegen O0
python3 tests/cxx-eh-rtti/native.py
python3 tests/cxx-eh-rtti/admission.py
python3 tests/cxx-eh-rtti/audit.py
python3 tests/cxx-eh-rtti/protection.py
python3 tests/cxx-eh-rtti/private_protection.py
python3 tests/cxx-eh-rtti/sdk_graphs.py
```

The two debugger runners need permission to trace their own SDK SIM subprocess.
They attribute failures to checks/terminating wrappers, rather than accepting a
signal alone. Private-state probes inject raw pointer arguments under GDB;
production services never expose private headers, TLS or unwind contexts.
The native harness reserves an actual alternate stack and image ranges, uses the
real allocator/checker/ABI adaptation, pinned SDK guards and the system libgcc
unwinder. Its test-only startup/atexit fixture executes the actual compiler
callback records on the reserved stack; it does not add production scheduling
services. Its synthetic layout/header allocator is auxiliary native evidence,
not another supported enclave backend or an SGX result.

`run.py` covers frontend and codegen O0/O2, BASELINE/RADIX_ONLY/MAC27 and MAC27 at
`0x140000000`. The core fixture executes 28 actions nine times; the libc++ fixture
adds eight library actions, including shared/weak ownership and error recovery.
Each completed protected ECALL
checks that private live/caught/uncaught exception state is empty. Native tests
also check complete buddy-heap reclamation, exact private allocation counts and
terminal exhaustion without raw fallback.
The current core fixture has 28 actions (252 ECALLs); libc++ adds eight actions
(324 ECALLs). Action 27 covers shared virtual bases, function-type identities
and SDK nonpublic/first-match repeated-base casts/catches. Action 35 exercises
shared ownership, weak locking/expiration, custom-deleter identity, destruction
and recoverable `bad_weak_ptr`.
Protected rows separately run action 130, the null virtual-pointer catch
correction; the original BASELINE SDK fault is recorded independently. The
2026-10-21 `collect.py` and October 23 `sdk_reuse.py` collectors/counts describe
their earlier implementations. `sdk_graphs.py` collects the current matrix.
The fixture's dynamic global constructor also throws/catches during SDK startup.
SDK SIM destruction is not used to infer automatic hardware teardown callbacks.

Keep `.integration.json`, `.trusted.json`, retained IR, `.ownership.json`, library
archives, bridge manifests and linker maps together. The mandatory ELF audit
invokes `audit_cxx_eh.py`: it checks all-unit mode/settings, hashes from source
through placement/link, output IR confinement, exact application symbols,
private metadata ownership, native bridge entries and pinned SDK archives.

Public/nonpublic bases, repetitions and shared virtual diamonds follow the
recompiled pinned SDK's graph behavior. Structural descriptor checks and all
memory checks remain active; no independent C++ conformance claim is made. Foreign EH,
`exception_ptr`, app TLS/threads, member/function-pointer exceptions, custom
personalities, unknown metadata and private-token escapes reject. Check reuse,
local proofs, fast paths and post-instrumentation InstCombine stay disabled for
this mode. Payload/header exhaustion is terminal; there is no emergency exception
reserve. Rounded-slot and temporal/CFI exclusions still apply.

See [step 21](../../docs/legacy/steps/21-cxx-eh-rtti.md) and the
[results and limits](../../evidence/2026-10-21-cxx-eh-rtti.md). No hardware,
full C++ conformance, arbitrary library compatibility or timing is claimed.
