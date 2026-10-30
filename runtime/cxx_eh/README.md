# Application exception ABI over the SDK unwinder

`runtime.cpp` adapts the small allocation/catch/personality protocol in Intel
SGX SDK 2.26's PathScale `sdk/cpprt/linux/exception.cc`. The original BSD notice
is retained in the source and `COPYING.PathScale`. `sdk-pins.json` pins the exact
reference source and ABI/DWARF headers. `prepare.py` verifies them and copies
only those reference files into a local build directory. The SDK installation
and its `_Unwind_*` implementation are unchanged.

Each application exception has an ordinary protected heap payload and a separate
SDK-heap `Node`: the original private `__cxa_exception` header, payload capability,
requested/rounded sizes, ownership link and throw state. Neither adjacency nor
an application-readable private header is used. The personality retains the
SDK's two-phase LSDA dispatch and calls the instrumented application matcher in
[apps/cxx-abi](../../apps/cxx-abi/README.md) for data/type traversal. Landingpad
pointers are private control tokens; the compiler confines their uses.

The private serial catch chain is separate from SDK C++ state. Exact application
ABI symbol routing leaves SDK-internal exceptions on the SDK's original ABI.
Foreign exceptions, force-unwind, retained handles, dynamic specifications and
application TLS/threads are rejected. Exceptions cannot escape generated ECALL
or SDK callback wrappers. SDK/runtime/protection failures stay terminal.

No emergency payload reserve is introduced. Recoverable ordinary-new failure
throws `bad_alloc` while exception allocation has capacity. Exhausting the
protected heap or private header allocator is terminal (`DEPLETED`), with no
raw allocation fallback. `runtime.h` exposes trusted diagnostics only; it is not
an application service or a source of application-visible private pointers.

[Step 21](../../docs/legacy/steps/21-cxx-eh-rtti.md), [reproduction](../../tests/cxx-eh-rtti/README.md)
and [evidence](../../evidence/2026-10-21-cxx-eh-rtti.md) describe the bounded support
and separate native/SIM results. No hardware, CFI, temporal safety or full C++
conformance is established.
