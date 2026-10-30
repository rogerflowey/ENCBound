# Shared serial application mutex stubs

**Mutex support: correctly stubbed for explicitly selected serial application
lock/unlock calls.** This shared component reuses the validated Crust adaptation.
`app_serial_mutex_lock` and `app_serial_mutex_unlock` return success without
reading, writing, validating or decoding their argument. They contain no state.

Compile [serial_mutex.cpp](serial_mutex.cpp) as application code through
`tools/encbound-cc.sh` with the full integration preset and the same flags/profile
as its callers. Collect its actual definitions in the application's admission
inventory, place the object and include it in the final application ownership
audit. Use the same adaptation in BASELINE, RADIX_ONLY and MAC27.

For each selected application translation unit, add:

```text
-include /absolute/path/to/apps/serial-mutex/serial_mutex_redirect.h
```

Apply that flag during both frontend inventory and application compilation.
The [header](serial_mutex_redirect.h) includes the SDK declarations first, then
redirects `sgx_thread_mutex_lock/unlock` to private application symbols. Calls
can alternatively use [serial_mutex.h](serial_mutex.h) directly. The C linkage
declarations are usable by C and C++ callers. The implementation remains a
separately compiled application C++ unit.

Keep the redirect out of SDK, runtime, bridge and other trusted compilation.
There is no link interposition and no raw SDK service admission. The stubs do
not replace any SDK mutex symbol. Review each application's selected source
closure instead of enabling the redirect globally; it is intentionally absent
from `config/integration.env`.

The required workload contract is:

- One active application invocation across all entries, with overlapping and
  nested/reentrant entry rejected by the trusted admission policy; one TCS alone
  does not establish this.
- The selected locks serve only mutual exclusion. The workflow must not depend
  on contention, lock ownership, error returns or synchronization with workers.
- Record omitted application synchronization as an adaptation. The stubs do not
  enforce the entry policy themselves and provide no concurrent locking.

The implemented API is the two SGX lock/unlock calls only. Init/destroy,
trylock/timed locking, condition variables, recursive-lock semantics, pthread
mutexes and the private `std::mutex` implementation closure need separate work.
Application threads/TLS remain outside the supported configuration.

## Validation and provenance

```sh
python3 apps/crust-selected/check_serial_mutex.py
```

Crust's original pinned `SafeLock` is the first consumer of the shared component.
The runner compiles and places both application units in all three profiles,
checks local symbol routing and tests 192 total gated sequences plus 192 nested
entry refusals. Native non-access controls include poisoned mutex fields, NULL,
an unreadable page and a noncanonical pointer. Omitting the redirect must fail
the routing oracle. Protected native rows use the real runtime and synthetic
platform; SDK-shaped spies are test-only.

The implementation is local code promoted from `apps/crust-selected`; that
directory's compatibility files forward to this single implementation. No SDK
mutex algorithm is copied. Upstream Crust source/license pins remain with its
recipe. See [fresh shared-component evidence](../../evidence/2026-10-23-shared-serial-mutex.md).
Native checks establish the stub contract and scoped routing. Each additional
application still needs its own serial-entry and workload evidence; no new
application SDK SIM/hardware result follows from sharing the source.
