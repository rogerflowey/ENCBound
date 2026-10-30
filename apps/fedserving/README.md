# Bounded FedServing combiner

This recipe runs the pinned upstream `combine_result` prediction aggregator in
SDK simulation with BASELINE, RADIX_ONLY, MAC27 and MAC27 above 4 GiB. It uses
the complete integration preset, including protected writable globals, across
the application and its private selected-libc closure. It does not run model
training or the upstream Python/GPU pipeline.

From the restart root:

```sh
tools/with-integration-defaults.sh python3 apps/fedserving/run.py
python3 apps/fedserving/trace.py
python3 apps/fedserving/confused_deputy.py
```

The second command uses GDB and requires process-tracing permission. Build,
audit, output, error and access-trace logs are retained under
`build/first10-2026-10-21/fedserving/`. The source defaults to `build/paper-sources/FedServing` pinned Git
checkout; `make -C apps/fedserving SOURCE=/path/to/FedServing` accepts another
checkout only when its revision and consumed files match [pins.json](pins.json).
LLVM 21.1.8 and the repository's pinned SDK 2.26/source paths are required.

The bounded configuration changes `QUERY_SIZE` from 7000 to 16. Six models, ten
categories, all twenty iterations and the original L2 functions remain. The
preparer adds the missing return from `init_model_inputs` and a pinned SDK-only
`sgx_tstdc.edl` import. Every adaptation and prepared-file hash is recorded.
The original ECALL and OCALL signatures are preserved.

Six sequential cases per image include zero predictions, identical models and
four heterogeneous prediction sets. An independent Python equation oracle
compares all six weights and 160 prediction values, with finite-value and
completeness checks. Five damaged-response controls must reject. The host also
checks transport/application results, unchanged input predictions and the
upstream-unwritten output iteration field. The oracle deliberately retains
the upstream `inputs[0].weight` denominator and the output-before-final-update
ordering; this is a reproduction of that implementation.

One upstream C++ unit and nineteen private library objects are compiled through
the same preset per image. The library contains the existing ten formatter
units/helper and eight additional pinned math/classification units. Its symbols
use `app_fmt_` names; SDK/runtime libraries keep their own names. Mandatory
audits bind source/header/compiler inputs, retained IR, object placement, exact
linked objects and archive bytes, generated bridges, SDK pins and signed-image
bytes. They verify ownership, startup order, metadata/base/extent and loaded
application page permissions. BASELINE bridge output must equal stock Intel
output.

The original `[user_check]` model input/output arrays remain caller-chosen
pointers. GDB attributes a 16-byte vectorized read in `cal_output` to
`encbound_require`, confirms canonical host acceptance and finishes all six
numerical cases in each protected image. This establishes an exercised check
path, without demonstrating tagged model storage or general vulnerability
prevention.

A separate baseline confused-deputy control passes an enclave-internal address
as `output`/`input` through the unchanged `[user_check]` ECALL
([probe](confused_deputy.c), [runner](confused_deputy.py)). BASELINE has no
pointer check and completes the ECALL, writing 1280 bytes of computed
predictions into enclave memory; six such writes followed by a read ECALL make
the enclave read its own memory and return a host-visible value matching an
independent oracle (3.3e-13 write / 3.2e-9 read maximum absolute difference).
RADIX_ONLY, MAC27 and high-base MAC27 trap with SIGILL in
`encbound_abort(ENCBOUND_ERR_POLICY=3)` before the first enclave-internal
access. This is SDK SIM only and uses `0x3d000` (BASELINE heap /
`.encbound.globalbss` in protected images) as a scratch target. The write is a
constrained 160-double write and the read returns a function of the target
region; arbitrary secret extraction and hardware behaviour are not established.

O2 promotes many numerical scratch arrays into registers. A successfully built
formatter body is not evidence that all its paths execute in these fixtures.
The 7000-query capacity, KL branch, arbitrary inputs, ML accuracy, hardware,
performance and general vulnerability prevention remain unestablished.

See [origin and licenses](PROVENANCE.md) and the
[included primary targets](../README.md).
