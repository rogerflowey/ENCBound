# Original wallet ECALL integration

Pinned upstream: `asonnino/sgx-wallet@8d15df13e1e37b95d233b3911b5e21ba32a8b962`
(MIT). See [source provenance](PROVENANCE.md). This recipe uses the current
modified Intel generator, original public ECALLs, checked sealing adapters and
repeated serial sessions. The original enclave C++ files are compiled as C.

From the artifact root, with the pinned SDK/source environment configured:

```sh
make
python3 tools/prepare-paper-sources.py --app sgx-wallet
for profile in BASELINE RADIX_ONLY MAC27; do
  tools/with-integration-defaults.sh make -C apps/sgx-wallet \
    PROFILE="$profile" APP_FRONTEND_OPT=-O2 APP_CODEGEN_OPT=-O2 \
    benign boundary upstream
done
```

`overflow-attribute` and `optimized-copy` are separate protected-profile targets
requiring GDB or machine-code attribution respectively. A failing build, ordinary
crash or unattributed signal is not a protection result. Keep BASELINE,
RADIX_ONLY and MAC27 outputs separate. This recipe retains its original low image
base and does not add a high-base wallet claim.

The [October 21 record](../../evidence/2026-10-21-first10-integrations.md) contains
the complete-preset O2 functional, boundary, original-host and attributed overflow
results. It also records the workload-specific absence of application data and
its strict inventory controls. Historical source/image identities are preserved;
packaging this recipe is not a new execution result. Hardware, performance,
temporal safety and general exploit prevention remain unestablished.
