# Selected ConFlow operators

Normal four-profile SDK SIM matrix: `python3 apps/conflow/run.py`.
Direct user-check control: `python3 apps/conflow/confused_deputy.py --trace`.
Shape controls, including their required hostile host:
`python3 apps/conflow/vuln.py`.

The original selected encode/decode, ReLU, sigmoid, softmax and gradient bodies
and their EDL declarations are pinned in pins.json. Source is fetched into
build/; no upstream source license was found at this pin. The admitted closure
uses checked RNG and instrumented formatter/math dependencies. Host math checks
normal outputs. Positive shape escape distinguishes MAC27 TAG rejection from
RADIX_ONLY's accepted adjacent slot; negative underflow and direct raw enclave
pointers have separate controls. These are bounded native/SDK SIM observations,
not hardware, full ML workflows, exact object bounds or general exploit claims.
See the root README and selected original records under evidence/.
