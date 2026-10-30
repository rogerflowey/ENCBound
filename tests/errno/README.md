# Application errno and EDL propagation acceptance

```sh
python3 tests/errno/run.py
```

Optional `--native-only`, `--sim-only` and `--build <directory>` select a run.
Each invocation writes a fresh `results.json` and command logs under
`build/integration/errno` by default. Run the full command for a combined record.
The runner builds the pass/generator and uses the full integration preset for
the C application, separate C++17 dependency and common C errno provider.

Six native rows execute actual emitted host/enclave bridges and the real
ENCBound runtime over a modeled linked-ELF platform, at O0/low base and O2/above
4 GiB in BASELINE, RADIX_ONLY and MAC27. Each runs 60 functional cases, five
copy failures, two transport failures and one OCALL allocation failure. Cases
cover separate-unit sharing, sequential persistence, explicit application writes,
marked and unmarked OCALLs, int/void/no-argument forms, positive/negative/zero
errno, success/failure return values and an unchanged host errno. A post-copy
mutation checks that the bridge uses the copied scalar without rereading host
marshaling memory. Failure controls assert unchanged application errno, Intel
status/return-copy ordering and cleanup.

Protected native rows also attempt raw application/SDK/table access, slot
crossing and (MAC27) tag corruption; each is attributed by the real abort code.
Provider ownership and missing/duplicate link negative controls are separate
from those protection results.

Four Intel SGX SDK SIM configurations execute the same 60-case oracle in
BASELINE, RADIX_ONLY, MAC27 and high-base MAC27. They verify SDK errno remains
separate from application writes, final ownership, source/build identities,
metadata, SDK pins and loaded page permissions. Two test-only trusted ECALLs
expose the SDK errno address/value for negative controls; these are fixture
oracles, not admitted application services. BASELINE raw reads/writes succeed.
Each protected configuration terminates both accesses with SIGILL, independently
attributed in GDB to `encbound_abort` code 3 from `errno_access`.

Native transport and SDK isolation are modeled in the native fixture. SDK SIM
uses the actual pinned SDK transport/libc, but provides no SGX hardware
isolation. Neither suite establishes hardware execution, performance, application
TLS/concurrency or a complete SQLite integration. The
[generic integration recipe](../../libc/README.md) describes production ownership
and the scalar bridge handoff.
