# YeeZ original analyzer/key-manager integration — 2026-10-24

This record covers the selected normal YeeZ workflow: the original multi-person
first-match analyzer and the original default key manager, linked and run through
their public ECALLs in SDK simulation. The application bodies and EDL files are
unchanged. The checked SDK services from the earlier
[service record](2026-10-24-yeez-sdk-services.md) remain a separate,
historical result.

## Selected closure

`apps/yeez/run.py` builds:

* `example/multi_personlist/first_match/enclave/eparser.cpp` with the original
  `eparser.edl` (12 ECALLs, 25 application OCALLs, five SDK-only);
* `ypc/keymgr/default/enclave/ekeymgr.cpp` with the original `ekeymgr.edl` and
  its ECC/stbox imports.

The selected first-match workload supports raw and sealed data sources and the
original default key-manager trust/provisioning path. `apps/yeez/execute.py`
signs both images with one ephemeral test key at
`0x40000000`/`0x80000000` (low) or `0x140000000`/`0x180000000` (high), compiles
the generated host bridges, the host OpenSSL/secp256k1/Keccak reference code and
the loaded-permission wrapper, and runs the host fixture.

The host is an independent wire encoder/oracle. It creates a master key through
the original `generate_ecc_key_pair`, provisions a data key through
`forward_private_key`, runs a real key-manager DH session, serves the selected
data/key-manager/log OCALLs, and independently checks the decrypted result, the
aggregate data hash, the result signature and the cost signature. It does not
expose an SDK private key. Unselected imported file/KV OCALLs abort visibly if
called rather than returning fake success.

## Fresh SDK SIM results

| Configuration | Analyzer/key-manager base | Raw | Sealed | Empty | Totals |
| --- | --- | --- | --- | --- | --- |
| BASELINE | `0x40000000` / `0x80000000` | 28-byte result | 28-byte result | 0-byte result | 47 total ECALL/host-callback calls, 350 checks, 3 DH handshakes, 5 key requests, 3 batches |
| RADIX_ONLY | `0x40000000` / `0x80000000` | 28-byte result | 28-byte result | 0-byte result | same |
| MAC27 | `0x40000000` / `0x80000000` | 28-byte result | 28-byte result | 0-byte result | same |
| MAC27 | `0x140000000` / `0x180000000` | 28-byte result | 28-byte result | 0-byte result | same |

Each normal run prints:

```text
YEEZ scenario=raw pass result_bytes=28
YEEZ scenario=sealed pass result_bytes=28
YEEZ scenario=empty pass result_bytes=0
YEEZ ORIGINAL ANALYZER SDK SIM PASS calls=47 checks=350 handshakes=3 key_requests=5 batches=3
```

The host verifies the raw and sealed results decrypt to
`Alice : ID-7 .Carol : ID-7 .` (28 bytes), checks the aggregate hash, verifies
the data/cost signatures, and confirms the empty source produces a zero-byte
result. The four records are in
`build/yeez/full-integration/<profile>/<low|high>/results.json`; the machine
record retains unsigned/signed image hashes, host hashes and the captured
output.

The same normal path was also re-run with the current `host.cpp` (the version
that adds the hostile modes) into
`build/yeez/c13-hostile-v1/normal-check/`; all four configurations again
reported the same 47/350/3/5/3 totals. That is a host-regression check, not a
new enclave build.

## What this establishes

* The selected original analyzer and key-manager ECALL/reachability closure
  links and runs in SDK simulation.
* The original raw and sealed first-match data paths produce the expected
  result; the empty path terminates cleanly.
* The original default key-manager provisioning, DH session, request/response
  and sealing path runs without a stubbed key exchange or SDK private-key
  exposure.
* BASELINE, RADIX_ONLY, MAC27 and high-base MAC27 all complete the selected
  normal workflow. This is not a protection comparison by itself; the hostile
  controls are separate records.

## What this does not establish

* Full YeeZ toolkit deployment, the original analyzer's other data sources,
  real chain/IPFS/offchain services, or the complete key-manager deployment.
* SGX hardware, timing, performance, concurrency/reentry, repeated-session
  behavior or availability.
* Any C13/C14/C15 protection claim; those are in the
  [C13/C14](2026-10-24-yeez-c13-c14-hostile.md) and
  [C15](2026-10-24-yeez-c15-hostile.md) records.
* Exact-object bounds, secret reachability or exploitability beyond the stated
  selected workflows.

## Reproduction

```sh
python3 apps/yeez/run.py --profile BASELINE
python3 apps/yeez/execute.py --profile BASELINE
python3 apps/yeez/run.py --profile RADIX_ONLY
python3 apps/yeez/execute.py --profile RADIX_ONLY
python3 apps/yeez/run.py --profile MAC27
python3 apps/yeez/execute.py --profile MAC27
python3 apps/yeez/execute.py --profile MAC27 --high
python3 apps/yeez/collect_integration.py
```

`execute.py --build-only` signs and compiles without running; `--signed-out`
keeps a separate signed/host directory. The unsigned images and `run.py`
outputs are consumed by both the normal and hostile runners.

## Identities

* Pinned upstream: `YeeZTech/YeeZ-Privacy-Computing` revision
  `d6eadeca03d04848ea462ab2602f155219b6d3c3`; recovered source under
  `build/yeez-blocker-assessment-final/source/`.
* Unsigned analyzer/key-manager SHA-256:
  * BASELINE `7d207048ec21a5f4a0189e1fd5e3ab223b6ede81791699ae16eafa5dec4f8220` /
    `c6a6e021e8b8be571f27549e774dec2ea21fdf5feef9ed359e233bfe7209e7a2`
  * RADIX_ONLY `8f1a1f77104e1175dbdd4e82888d1fa314b15abb035b2b311c31c2564dad17a8` /
    `d205ea131df69fd96912b1cf1972d37eaad3afe6d6de7e970ce7d870b7c9eb30`
  * MAC27 `9271da61fc9f15947e37f5e4c8b9a3081fe0bce2d1dc70cb9b680be4ae109c0b` /
    `9f3e9449cc7db3b7a4ffe6829567cb0fb85fe392ba6584757047ea5aedf906d5`
* Per-configuration signed image and host hashes are in
  [`2026-10-24-yeez-integration.json`](2026-10-24-yeez-integration.json).
