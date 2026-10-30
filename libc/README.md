# Serial application errno

`errno.c` and the headers in `include/encbound_app_libc` are original ENCBound
support code; no external implementation is copied. The errno constants and
underlying declarations come from the application's selected libc headers.

New integrations use `config/integration.env`, which sets `ENCBOUND_APP_ERRNO=1`.
The application compiler driver then prepends the errno header overlay. Both
the SDK `__errno` and system-header `__errno_location` spellings resolve to
`__encbound_app_errno_location`; ordinary source continues to use `errno`.
Use the same overlay during frontend/inventory probes and across all application
and dependency units. Keep host, generated trusted bridge, SDK and runtime
compilation on their ordinary headers.

Compile `libc/errno.c` through `tools/encbound-cc.sh` with the application's
profile, preset and actual-definition inventory, then apply application data
placement and link it **once per enclave application/library closure**. Include
its two actual definitions in that inventory:

```text
__encbound_app_errno_location
__encbound_app_errno_store
```

The selected formatter builder already supplies this object; a closure using
that builder must reuse it. The libc++ builder uses the common declarations and
inventory but does not add a second provider. Preserve the provider's retained
IR, `.integration.json` and `.ownership.json`; run the complete final-image
ownership audit. It checks the provider's application ownership, source/build
identity, profile, unique definition, final link and absence of raw application
errno references. Missing and duplicate providers also fail linking when used.
The bare compiler driver keeps `ENCBOUND_APP_ERRNO=0` for historical fixtures.

Configured application OCALLs marked `propagate_errno` keep Intel's host errno
capture and existing marshaling/copy-error ordering. After the guarded copy into
SDK-private errno succeeds, generated trusted code passes only that copied
integer to `__encbound_app_errno_store`. The store is instrumented application
code; no SDK pointer or private TLS address enters the application environment.
Unmarked OCALLs leave application errno unchanged. Successful OCALLs propagate
the captured value too, including an unchanged host errno; zero or negative
integers are transported without interpretation. Transport/allocation/copy
failures leave application errno unchanged. SDK-only imports keep SDK semantics.

The cell persists across sequential calls and follows the application's global
placement/protection mode. It is ordinary mutable application state and does
not provide integrity against writes through valid application capabilities.
This is the existing serial, nonreentrant application configuration; it does
not provide application TLS or thread/reentrant errno semantics.

Run `python3 tests/errno/run.py`. See the [test recipe](../tests/errno/README.md)
and [dated evidence](../evidence/2026-10-23-propagate-errno.md) for native versus
SDK SIM results, failure ordering and attributed private-state controls.
