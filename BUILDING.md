# Building and reproducing ENCBound

## Prerequisites

Use Linux x86-64, the pinned Clang/LLVM 21 toolchain, Intel SGX SDK 2.26.100.0
and its matching source checkout, GNU Make, Python 3.12 or newer, GCC/G++,
binutils, OCaml/ocamlbuild, OpenSSL, curl, Git, GDB and taskset. Source pins are
experimental dependencies, not claims about current releases. Paths are
configurable; commands below run from this directory.

```sh
export SGX_SDK=/path/to/sgxsdk
export PINNED_SRC=/path/to/intel-sgx-simulation-2.26
make
python3 tools/check_sdk_pins.py --sdk "$SGX_SDK" --pinned "$PINNED_SRC"
make test
make bridge-test
# Optional native and SDK SIM compatibility checks:
make compatibility-test
```

Without these variables, most recipes look under `deps/sgxsdk` and
`deps/intel-sgx`. `sgx-fs` deliberately uses its separate repo-local dependency
route described below. Generated objects, IR, manifests, logs, source caches and
fresh ephemeral signing keys belong under `build/`.

## Selected application recipes

ConFlow fetches and verifies its source automatically. Its normal command runs
BASELINE, RADIX_ONLY, MAC27 and high-base MAC27 with independent math oracles.

```sh
make smoke
python3 apps/conflow/confused_deputy.py --trace
python3 apps/conflow/vuln.py
```

Prepare the selected source closures from their exact revisions and hashes.
Existing local checkouts can be used with `--from-cache NAME=/path/to/checkout`;
every recorded file hash is still checked.

```sh
python3 tools/prepare-paper-sources.py
python3 apps/sgx-kms/test_adapters.py
python3 apps/sgx-kms/run.py --build build/sgx-kms/paper
python3 apps/sgx-kms/c16_protection.py --build build/sgx-kms/paper --trace

tools/with-integration-defaults.sh python3 apps/sqlite-sgx/run.py

python3 apps/yeez/test_adapters.py
python3 apps/yeez/test_full_adapters.py
for profile in BASELINE RADIX_ONLY MAC27; do
  python3 apps/yeez/run.py --profile "$profile"
  python3 apps/yeez/execute.py --profile "$profile"
done
python3 apps/yeez/execute.py --profile MAC27 --high
python3 apps/yeez/hostile_control.py
python3 apps/yeez/c15_control.py
```

The sgx-fs recipe fetches its own pinned application, SDK package and Intel source
into this artifact's build tree; it does not execute the SDK installer. Run it
with the external SDK overrides unset so its repo-local path checks remain valid.

```sh
python3 apps/sgx-fs/prepare.py
env -u SGX_SDK -u PINNED_SRC python3 apps/sgx-fs/run.py
env -u SGX_SDK -u PINNED_SRC python3 apps/sgx-fs/f2_control.py
```

General benchmarks have separate timing and memory protocols. Use a fresh output
directory. Do not treat validation smoke timings as benchmark measurements.

```sh
python3 apps/general-bench/run.py --out build/bench-paper
python3 tests/general_bench_test.py --run build/bench-paper
python3 apps/general-bench/memory.py --out build/memory-paper
python3 tests/general_bench_memory_test.py --run build/memory-paper
```

## Evidence and limits

`VALIDATION.json` describes checks performed for the October 30 selection update.
`VALIDATION-2026-10-27.json` retains the original export validation unchanged.
Both are separate from the original dated records in `evidence/`. Historical
absolute paths and build identities
in those records describe their original runs; they are not runtime dependencies
or results for the exported scripts. Fresh evidence defaults to `build/evidence/`.
No historical result is relabeled as a fresh run. Hardware and performance
measurements were not performed during export validation.

SQLite C03 rejects a PROTECTED target in `encbound_bridge_string`; it does not
establish a later SQLite access rejection. COMPAT read-only targets remain
admitted, and the benign control leaves TMPDIR/SQLITE_TMPDIR unset. YeeZ's small
`sign_message` output is a documented RADIX_ONLY slot-granularity limitation;
MAC27's TAG rejection is an authentication result. The selected application
closures are bounded integrations, not full deployments or universal prevention.

## Juliet

The pinned C pilot includes the runner, adapted scalar-output oracle, source
selection rules, evaluation report and original 129-case/774-row records. It is
separate from the primary-target application count. Its original configuration
is frontend/codegen O0 and SDK simulation; the records do not establish full
Juliet coverage or runtime overhead.

```sh
mkdir -p build/juliet/download
curl -fL --retry 2 -o build/juliet/download/juliet-1.3.zip \
  https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
make juliet-test
make juliet
```

The runner verifies the archive SHA-256 before extraction and uses a fresh output
directory for each run. Read [the report](tests/juliet/EVALUATION.md) for the
attributed-rejection counts and their limits. Normal bad-case returns are not
proof of prevention or containment.

## Protection scope

The implementation protects admitted application/dependency heap and stack
slots, and writable-global slots when enabled. The SDK, bridge, allocator
metadata, pointer key, runtime and checked adapters remain trusted. Execution
must follow admitted code and trusted call paths. MAC27 authenticates slot/domain
identity; RADIX_ONLY omits authentication; BASELINE uses ordinary SDK pointers.
Bounds cover rounded slots. There is no exact-object-bounds, temporal-safety,
CFI, trusted-code-bug, side-channel or availability guarantee. Retained pointers
to returned application frames must not be used after trusted frames reuse the
shared SDK stack. Outside host memory remains untrusted. SDK simulation provides
no SGX hardware isolation.

## Source and artifact provenance

Source and selected evaluation material initially exported on 2026-10-27, with
the artifact selection updated on 2026-10-30. The package contains the mechanism,
all 13 completed bounded primary-target integrations, Juliet and five benchmark
kernels. See [the target matrix and additional recipes](apps/README.md).
`EXPORT.json` records the source revision,
selection, original file hashes and export adaptations. `CONTENTS.txt` lists
packaged files; `MANIFEST.sha256` verifies their bytes.

No new
license is assigned to original ENCBound code. Third-party notices, licenses,
source hashes and adaptation patches accompany retained components. Upstream
application sources are fetched into ignored `build/`; the small
sk-sgx closure is retained with its original notices and hashes. Source/license
limits are recorded in each workload's provenance file.
