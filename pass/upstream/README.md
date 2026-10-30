# Pinned LLVM variadic expander

`ExpandVariadics.cpp` is adapted from LLVM tag `llvmorg-21.1.8`, file
`llvm/lib/Transforms/IPO/ExpandVariadics.cpp`:
https://github.com/llvm/llvm-project/blob/llvmorg-21.1.8/llvm/lib/Transforms/IPO/ExpandVariadics.cpp

The original file SHA-256 is
`559e4511cf502f6991e3a39f4a5e598096e54201e699005b39873de876f44131`.
LLVM's Apache-2.0 WITH LLVM-exception license and notices are retained in
`LICENSE.TXT`; its SHA-256 is
`8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`.

`encbound.patch` records the delta from that original. The adaptation gives the
copy its own namespace and a fixed Lowering entry, removes public LLVM pass
registration and command-line override, adds a call-wide target frame hook and
registers the x86 class in `../encbound_x86_variadics.h`. The original sequential
builder remains the default for the upstream target classes. Tail-call-kind
handling applies to the replacement call. This copy is compiled into our plugin;
the installed LLVM toolchain and SDK are unchanged.

The bounded C++ EH adaptation preserves `invoke` normal/unwind destinations
when packing a variadic call. Its fixed caller frame is reclaimed by normal
stack unwinding; no lifetime-end instruction is inserted after an invoke.
Validated personality-only declarations retain the unwinder's native ABI and
are excluded from argument-buffer lowering. Separate-unit throwing variadic
calls are exercised by `tests/cxx-eh-rtti/run.py` at frontend/codegen O0/O2.

`../encbound_variadics.h` establishes the application-only ownership and private
ABI before invoking the copied transform. Only Linux x86-64 scalar calls are
admitted by that entry. Existing upstream GPU/Wasm classes are retained as
source context, not additional supported ENCBound backends.

The October 23 application-callback extension reuses two existing Lowering-mode
operations in this pinned source: replacement of all address uses with the fixed
entry, and the final instruction scan that expands indirect variadic calls with
the existing x86 frame hook. No new upstream-source delta is needed. Admission
requires the application variadic and callback switches together, preserves the
private version/signature/profile names and adds address/indirect ABI records.
The final ownership audit binds those records to retained application builds.
See [execution and closure tests](../../tests/variadic-callbacks/README.md).

Reproduction and new semantic/protection tests: `make -C pass test`, including
`tests/pass/variadics_test.py`. Those tests compare automatic packing with a
separately compiled native ABI oracle on an actual alternate machine stack and
execute the real checked runtime. They do not run SGX or the upstream GPU tests.
