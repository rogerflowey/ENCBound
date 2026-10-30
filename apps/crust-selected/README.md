# Crust selected incomplete-transfer path

This implements the owner's requested mutex stubs for the C01 incomplete-transfer
path at `crustio/crust-sworker` revision
`a109e0a60a4ea256d884fde192b06b025e8bd6b1`. It removes synchronization from the
evaluated application workload. Mutex lock/unlock is correctly stubbed for this
serial scope using the [shared component](../serial-mutex/README.md).

The owner also authorized stubbing/removing the restore dependency. The selected
workload now supplies a [terminal application callback](restore_stub.cpp) for
`ecall_restore_from_upgrade`, retaining the original dispatch initializer.
Completion aborts; the original incomplete-transfer body, allocation, pool reuse
and copy remain unchanged. These adaptations close the two previously identified
application admission blockers. The selected incomplete-transfer enclave now
builds, passes final ownership/startup audits and runs in SDK simulation.

The [hostile C01 control](hostile_control.py) then exercises the unchanged
two-call stateful sequence: it retains a 256-byte buffer, reuses it with the same
key, and asks the original body for a 1,024-byte copy at offset 2,048. BASELINE
executes the raw write; RADIX_ONLY and MAC27 reject it with
`ENCBOUND_ERR_RANGE` before the write. See
[the protection record](../../evidence/2026-10-23-crust-c01-hostile.md).

## Run the selected enclave

```sh
python3 apps/crust-selected/run.py
```

The runner builds isolated tooling and freshly rebuilds the complete selected
26-object private-libc++ closure for each profile. It links/audits 33 application
objects per image: the library, selected function/pool, dispatch map, redirected
`SafeLock`, shared mutex stubs, terminal restore stub, application snapshot helper
and common errno provider. SDK/runtime/bridge objects remain trusted.

Four SDK SIM configurations pass: BASELINE, RADIX_ONLY and MAC27 at
`0x40000000`, plus MAC27 at `0x140000000`. Each runs 90 calls with 44 snapshots
comparing 22,016 bytes. Sessions cover empty, tiny and 4,095-byte chunks; three
retained buffers; repeated/interleaved updates; a larger declared total that
reuses the original allocation; allocation-capacity failure; copied-buffer
overflow rejection; and successful calls after both errors. Snapshot observations
are application-instrumented test ECALLs and export bytes/counts, never pointers.

Loaded text/data permissions, raw-access region isolation, exact pinned SDK
archives, complete private application symbol closure, and protected initializer
ordering are checked. All four protected ECALL bridges hold the trusted serial
gate; an invoked diagnostic confirms nested admission fails while the bridge is
active. BASELINE retains stock Intel bridge output and the finite host executes
serially with one TCS. No concurrent/reentrant application workload is admitted.

A separate completing-transfer process reaches the stub and terminates with
SIGILL in each configuration. Debugger traces bind it to
`ecall_safe_store2 → ecall_restore_from_upgrade → encbound_cxx_fail → SDK abort`.
This is expected terminal completion, not a protection result.

Outputs default to `build/crust-selected/enclave-v1/all-compat-v1/`;
`--out-dir` selects isolated output and repeated `--profile` selects profiles.
Both MAC27 bases run when MAC27 is selected. Recheck any final image with:

```sh
python3 apps/crust-selected/audit.py --build \
  build/crust-selected/enclave-v1/all-compat-v1/MAC27-0x40000000
```

See [the integration evidence](../../evidence/2026-10-23-crust-selected-integration.md).
The original hostile C01 sequence is observed separately below. Hardware, real
restoration, repeated-session exhaustion, completed-transfer cleanup and
performance remain unevaluated.

The shared `apps/serial-mutex/serial_mutex.cpp` defines private application functions
`app_serial_mutex_lock/unlock`. Both return success without reading,
writing, decoding or following the argument. Compile this source through the
application driver under the full integration preset in every profile.

Force-include the shared `serial_mutex_redirect.h` **only when compiling the original
`SafeLock.cpp`**. The header includes the SDK declarations first, then redirects
the two calls to the private application symbols. Original `SafeLock` bookkeeping
and destructor behavior remain. No SDK mutex definition is replaced, and no
redirect is applied to SDK/runtime/bridge compilation.

This adaptation requires one active application invocation. The protected
bridges reject nested/overlapping entry through the trusted serial admission
gate; the stubs do not enforce that gate themselves. The current recipe uses one
TCS in all profiles, a serial host, no selected application OCALLs and no
concurrent/reentrant workload. Retain those conditions in any extension.

## Terminal restore callback

Compile [restore_stub.cpp](restore_stub.cpp) through the application driver with
the full preset and the same library/header flags as the selected source. Its
actual definition belongs in the application inventory and its placed object
belongs in the application link/audits in BASELINE, RADIX_ONLY and MAC27.
Include [restore_stub.h](restore_stub.h) in the split dispatch unit. Do not link
the original real restore wrapper alongside this definition.

The stub calls `abort()` without reading its buffer or size; the existing
no-exception terminal adapter handles that call. It never returns a successful
restore result. The original map still stores its address, so unknown dispatch
behavior has not been hidden by deleting the map or the earlier copy.
Only incomplete transfers are the selected application workflow. A completed
transfer terminates before the original post-callback cleanup; it does not
establish restore, completed-transfer cleanup or recovery support.

```sh
python3 apps/crust-selected/check_restore_stub.py
```

This runner verifies the expanded source/license pins, extracts the exact
original `ecall_safe_store2` body and both maps into split application units,
and uses the existing prepared private-libc++ inputs. It freshly collects
definitions from the 26 configured library sources and five application units.
All five application units compile and place in each profile; a relocatable
application link resolves the callback definition. The original hostile-copy
length still reaches `encbound_memcpy` in both protected profiles.

Nine native callback cases (NULL, PROT_NONE and a noncanonical pointer with
`SIZE_MAX`, in each profile) terminate with SIGABRT using the actual terminal
adapter. The native driver is trusted test code, separate from the application
pass. Omitting the callback's definition from admission must reproduce the
protected dispatch rejection. These checks establish object admission, callback
resolution and terminal behavior, not execution of the selected transfer body.

Outputs default to `build/crust-selected/terminal-restore-v1/all-compat-v1/`;
`--checkout` and `--out-dir` select the pinned checkout and isolated outputs.
See [the result](../../evidence/2026-10-23-crust-terminal-restore.md).

## Reproduce the mutex checks

```sh
python3 apps/crust-selected/check_serial_mutex.py
```

The runner consumes the existing pinned screening checkout; `--checkout PATH`
overrides its location and `--out-dir PATH` selects isolated output. `SGX_SDK`
selects SDK headers; the default is the existing pinned SDK 2.26 installation.
All outputs default to
`build/crust-selected/shared-serial-mutex-v1/all-compat-v1/`.

The runner verifies [pins.json](pins.json), extracts the two original `SafeLock`
files and LICENSE with `git show`, and builds the same two application units in
BASELINE, RADIX_ONLY and MAC27. It collects actual definitions, checks every
application manifest's full preset and places the resulting application objects.
The scoped redirect is present during both frontend inventory and application
compilation; it is absent from all trusted compilation commands.

Each native driver runs 64 serial sequences with the original `SafeLock`
methods and 64 nested-entry rejections. Protected rows use the real checking
runtime over the existing synthetic platform and a protected heap object for
`SafeLock`. Direct stub calls cover poisoned mutex fields, NULL, an unreadable
page and a noncanonical pointer encoding, checking that no pointee access occurs.
Mutex bytes remain unchanged. This is the stub's non-access contract, not
validation of those pointers or a protection result.

`native.cpp` is a trusted **test driver only**. Its SDK-shaped spies verify that
ordinary SDK-named calls remain separate from the application stubs. They are
not SDK mutex implementations and must not be linked into an enclave. The
negative control omits the scoped redirect: the same native oracle must exit
42 after observing escaped raw calls.

## Scope and provenance

The application driver, memory checks, protected-global mode and SDK/runtime
implementations are unchanged. No raw SDK service is admitted. The mutex
argument carries no authority because the application stubs perform no access.
The six resulting application objects compile and the three bounded native rows
pass. See [the shared-component evidence](../../evidence/2026-10-23-shared-serial-mutex.md);
the earlier Crust-only record retains its original paths and configuration.

The earlier
[selected-path assessment](../../evidence/2026-10-23-crust-selected-blockers.md)
records the original two dependencies; the mutex and terminal-restore adaptations
close those selected application admission stops. The subsequent SDK SIM recipe
above establishes the adapted incomplete-transfer integration. These bounded
native component checks remain separate from SDK SIM execution. There is no
full storage-worker deployment, hardware or performance claim; the focused C01
spatial rejection is recorded separately below.

The reused `SafeLock.cpp`, `SafeLock.h`, selected function, globals and consumed
headers come from the pinned upstream source; exact file/body hashes and the
repository LICENSE hash are in `pins.json`. The original
GPLv3 license text is retained with each extracted build source set. The private
stubs, scoped redirect, runners and native drivers are new local code.
The old local stub/header paths now forward to the shared implementation for
compatibility; the current runner consumes the shared files directly.

## Hostile C01 two-call control

```sh
python3 apps/crust-selected/run.py
python3 apps/crust-selected/hostile_control.py \
  --evidence evidence/2026-10-23-crust-c01-hostile.json
```

[hostile_control.py](hostile_control.py) compiles [hostile.c](hostile.c) against
the existing four signed images and calls the unchanged public
`ecall_safe_store2` twice with the same `buffer_key`:

1. `total_size=0x100`, `partial_size=1`, `offset=0` retains a 256-byte buffer.
2. `total_size=0x1000`, `partial_size=0x400`, `offset=0x800` reuses it and calls
   `memcpy(buffer+0x800, data, 0x400)`.

Because `offset+partial_size < total_size` in both calls, the terminal restore
stub is not reached. BASELINE executes the raw copy and both calls return
`CRUST_SUCCESS`. RADIX_ONLY and MAC27 (both image bases) terminate with SIGILL;
gdb attributes the stop to `encbound_abort(code=4)` through `encbound_require`
(width 1,024, write) and `encbound_memcpy` at `ecall_safe_store2`. The rejected
capability has a 256-byte slot and offset `0x1000900`, i.e. the first-call
buffer advanced by 2,048 bytes.

`--build` runs the integration matrix first; `--builds` and `--out` select
other image/output directories. The driver does not alter the application,
EDL, bridge or trusted runtime. The control establishes the adapted serial
incomplete-transfer path only: no hardware, unbounded-write, secret-reachability,
completed-restore, C02 replication or performance result. See
[the record](../../evidence/2026-10-23-crust-c01-hostile.md).

The enclave link/sign/layout scaffold and closed inventory/page checks reuse
this repository's STL service and SGX-KMS recipes. Private-libc++ provenance and
licenses are recorded in [its origin record](../libcxx/PROVENANCE.md); prepared
sources retain their original notices and `LICENSE.TXT`. No additional upstream
algorithm or raw SDK application service is introduced.
