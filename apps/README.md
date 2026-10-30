# Included primary target integrations

This artifact includes all **13 primary-58 repositories** with completed bounded
integrations recorded in ENCBound-restart as of 2026-10-30, across 12 recipe
directories. POSUP and TrustFL share a recipe. Membership, source revisions and
selected scopes are recorded in [primary-targets.json](../config/primary-targets.json).
The survey datasets themselves are excluded.

“Completed” refers to the selected ECALL and dependency closure described below.
Each original evidence record states its tested profiles, application adaptations,
oracles, protection observations and remaining limits. These are SDK simulation
integrations, with separate native controls where recorded. They do not establish
complete upstream deployments, SGX hardware behavior or fresh performance results.

| Target | Completed selected workload | Original evidence |
| --- | --- | --- |
| [ConFlow](conflow/README.md) | Eight encoding/activation/gradient ECALLs | [Integration](../evidence/2026-10-21-conflow.md) |
| [SGX-KMS](sgx-kms/README.md) | Current-session crypto workflow and C16 carrier control | [Session](../evidence/2026-10-23-sgx-kms-c16-session.md) |
| [YeeZ](yeez/README.md) | Original selected analyzer/default key manager, raw/sealed/empty | [Integration](../evidence/2026-10-24-yeez-integration.md) |
| [SGX_SQLite](sqlite-sgx/README.md) | Serial Unix-VFS temp-file workflow and C03 control | [C03](../evidence/2026-10-26-sqlite-c03.md) |
| [sgx-fs](sgx-fs/README.md) | Selected filesystem workflow and F2 cross-file disclosure control | [F2](../evidence/2026-10-21-sgx-fs-f2.md) |
| [sgx-wallet](sgx-wallet/README.md) | Original public wallet ECALLs, sequential sessions and original host | [Full-preset wallet rows](../evidence/2026-10-21-first10-integrations.md) |
| [FedServing](fedserving/README.md) | Six-model, 16-query L2 combiner with independent numerical oracle | [Bounded combiner](../evidence/2026-10-21-first10-integrations.md) |
| [go-consensus USIG](go-consensus-usig/README.md) | Serial enclave component with independent Ed25519/P-256/HMAC oracles | [Integration](../evidence/2026-10-21-go-consensus-usig.md) |
| [sk-sgx](sk-sgx/README.md) | Complete non-debug ten-unit enclave closure and provider oracle | [Integration](../evidence/2026-10-21-sk-sgx.md) |
| [ObliDB](oblidb/README.md) | Four selected linear-scan block operations and original user-check pointer | [Workload/control](../evidence/2026-10-23-oblidb-user-check.md) |
| [POSUP](posup-trustfl/README.md) | `ecall_getPathID` and `ecall_setFileIDs`, plus test observation | [Required ECALLs](../evidence/2026-10-23-posup-trustfl.md) |
| [TrustFL](posup-trustfl/README.md) | `ecall_init` and the full 60,000-record preprocessing loop | [Required ECALLs](../evidence/2026-10-23-posup-trustfl.md) |
| [Crust](crust-selected/README.md) | Incomplete-transfer `ecall_safe_store2`, serial mutex adaptation and terminal restore callback | [Selected integration](../evidence/2026-10-23-crust-selected-integration.md) |

The five general benchmark kernels and the required library/RTTI support remain
included. They are separate from this primary-target count. The Juliet suite is
under [tests/juliet](../tests/juliet/README.md).

## Prepare sources

Configure `SGX_SDK` and `PINNED_SRC` as described in the root README, then build
the tools and prepare source inputs:

```sh
make
python3 tools/prepare-paper-sources.py
```

The source helper verifies exact hashes. For FedServing, ObliDB, POSUP, TrustFL,
Crust and wallet it preserves the pinned Git commit because the existing
preparers read committed source or require its exact revision. It can use local
caches with `--from-cache NAME=/path/to/checkout`. These sources are stored under
ignored `build/paper-sources/`; source checkouts and their Git state are excluded
from the source package. USIG also uses this source directory. The small sk-sgx
source closure is bundled unchanged, with pins and original notices.

## Additional application commands

The root README retains the five original application recipes. Run these added
recipes from the artifact root. Use a fresh output tree for a new experiment;
retain original evidence rather than overwriting it.

```sh
# Original wallet: all three profiles, complete preset, matched O2 pipeline.
for profile in BASELINE RADIX_ONLY MAC27; do
  tools/with-integration-defaults.sh make -C apps/sgx-wallet \
    PROFILE="$profile" APP_FRONTEND_OPT=-O2 APP_CODEGEN_OPT=-O2 \
    benign boundary upstream
done

# Four configurations, with independent numerical and crypto oracles.
tools/with-integration-defaults.sh python3 apps/fedserving/run.py
python3 apps/go-consensus-usig/run.py

# sk-sgx: scalar frontend, complete selected enclave closure.
for profile in BASELINE RADIX_ONLY MAC27; do
  python3 apps/sk-sgx/probe.py --profile "$profile" --scalar \
    --out "build/sk-sgx/paper/$profile"
  python3 apps/sk-sgx/finish.py --build "build/sk-sgx/paper/$profile" \
    --base 0x40000000
done
# High-base MAC27 needs a separate fresh probe directory before finish.py.

# Original ObliDB selected functional host plus user-check control.
tools/with-integration-defaults.sh python3 apps/oblidb/user_check.py \
  --trace --high-base

python3 apps/posup-trustfl/run.py --app POSUP
python3 apps/posup-trustfl/run.py --app TrustFL
python3 apps/posup-trustfl/confused_deputy.py --trace

python3 apps/crust-selected/run.py
python3 apps/crust-selected/hostile_control.py
```

Source, SDK and compiler checks stay enabled. GDB attribution requires permission
to trace child processes. Per-application READMEs describe native controls,
additional hostile cases, recorded adaptations and full-workflow exclusions.
New command output belongs under `build/`, including `build/evidence/`.
