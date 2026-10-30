# YeeZ C13/C14 hostile `next_data_batch` control — 2026-10-24

This record executes the selected C13/C14 field through the original multi-person
first-match analyzer ECALLs. The original application, EDL, provider, bridge and
trusted runtime bodies are unchanged. Only the untrusted host callback is
hostile: at its first `next_data_batch` call it returns an enclave address and a
32-byte length instead of a host batch buffer. BASELINE performs the original
copy; RADIX_ONLY and MAC27 reject the checked source read before the raw copy.

The normal raw/sealed/empty workflow was already run on the same audited images
(`build/yeez/full-integration/*/low|high/results.json`). This control uses the
same images and the original public ECALL sequence; it does not replace or
relabel the normal evidence.

## Hostile pointer

The target is the original analyzer's static 64-byte `aad_mac_text` object
(first 21 bytes `tech.yeez.key.manager`). It is a real application global, not a
test buffer:

| Image | Symbol address | Section | Platform region |
| --- | --- | --- | --- |
| BASELINE | `0x402d4000` | `.encbound.apprw` | no checked runtime |
| RADIX_ONLY / MAC27 low | `0x40337000` | `.encbound.globalrw` | PROTECTED / GLOBAL |
| MAC27 high | `0x140337000` | `.encbound.globalrw` | PROTECTED / GLOBAL |

The host is given the address and length through `YEEZ_HOSTILE_PTR` and
`YEEZ_HOSTILE_LEN`; gdb only observes the resulting copy or check. No gdb memory
write injects the pointer, and no test allocator or fake interface is used.

## Sequence

For one fresh analyzer/key-manager enclave pair the host:

1. creates and provisions the normal key-manager session;
2. calls `init_data_source` with a raw or sealed source descriptor;
3. calls `begin_parse_data_item`;
4. calls `parse_data_item` with the normal encrypted query parameter;
5. on the analyzer's first `next_data_batch`, returns
   `*data = aad_mac_text`, `*len = 32`.

The original raw provider then executes `stbox::bytes sealed_data(32)` followed
by `memcpy(sealed_data.data(), t_sealed_data, 32)`; the sealed provider performs
the same copy before decrypting. Those are the C13 and C14 paths.

## Results

Eight SDK SIM rows were run: BASELINE, RADIX_ONLY, MAC27 and high-base MAC27,
each with raw and sealed input.

| Configuration | Mode | Observable result | Attribution |
| --- | --- | --- | --- |
| BASELINE | raw | copy executes; hostile run survives | gdb at application `memcpy` with source `0x402d4000 <aad_mac_text>`, `n=32`; destination receives `74 65 63 68 ...`; provider logs `make_package got: cxxrt::bad_alloc` |
| BASELINE | sealed | copy executes; process then stops with SIGILL | same copy from `aad_mac_text`; the original sealed decrypt path raises an uncaught exception and the original EH entry calls `abort`, not `encbound_abort` |
| RADIX_ONLY | raw | SIGILL | `encbound_abort(code=3)` <- `encbound_require(width=32, kind=1)` <- `encbound_memcpy(src=0x40337000 <aad_mac_text>, n=32)` <- `raw_data_provider::process` |
| RADIX_ONLY | sealed | SIGILL | same source check before the copy in `sealed_data_provider::process` |
| MAC27 | raw | SIGILL | same `code=3` policy rejection at `0x40337000` |
| MAC27 | sealed | SIGILL | same `code=3` policy rejection at `0x40337000` |
| MAC27 high | raw | SIGILL | same `code=3` policy rejection at `0x140337000` |
| MAC27 high | sealed | SIGILL | same `code=3` policy rejection at `0x140337000` |

`code=3` is `ENCBOUND_ERR_POLICY`: the source is an untagged address in a
protected application region. The raw `memcpy` is not reached. The archived gdb
excerpts for the low RADIX/MAC27 rows are reproduced below.

```text
Breakpoint 2, encbound_memcpy (dst=0x... <capability>,
    src=0x40337000 <aad_mac_text>, n=32) at runtime/adapters.c:20
HOSTILE_CHECKED_MEMCPY
#0 encbound_memcpy (...) at runtime/adapters.c:20
#1 ypc::raw_data_provider::process (...) at raw_data_provider.h:50
...
0x40337000 <_ZL12aad_mac_text>: 0x74 0x65 0x63 0x68 0x2e 0x79 0x65 0x65
0x40337008 <_ZL12aad_mac_text+8>: 0x7a 0x2e 0x6b 0x65 0x79 0x2e 0x6d 0x61
0x40337010 <_ZL12aad_mac_text+16>: 0x6e 0x61 0x67 0x65 0x72 0x00 0x00 0x00
0x40337018 <_ZL12aad_mac_text+24>: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00

Breakpoint 3, encbound_abort (code=3) at sdk/platform_layout.c:456
#0 encbound_abort (code=3)
#1 encbound_require (capability=1077112832, width=32, kind=1)
#2 encbound_memcpy (dst=..., src=0x40337000 <aad_mac_text>, n=32)
#3 ypc::raw_data_provider::process (...) at raw_data_provider.h:50
```

The BASELINE raw trace shows the same source bytes being copied into the
enclave destination. The sealed BASELINE SIGILL is separately attributed to the
original `abort`/EH path, so it is not counted as an ENCBound rejection.

## What this establishes

* The unchanged selected raw/sealed providers reach `next_data_batch` through
  the original public ECALLs after a valid key-manager session.
* The original EDL `[out] uint8_t **` slot accepts the hostile pointer, and the
  original provider copies the 32 bytes in BASELINE without a domain/range
  check.
* RADIX_ONLY and MAC27 reject that same source read before the raw copy with
  `ENCBOUND_ERR_POLICY` (3), at both low and high image bases, in both raw and
  sealed providers.
* The normal raw/sealed/empty result path remains unchanged.

## What this does not establish

* No secret reachability, disclosure or exploitability: the read is a bounded
  32-byte copy from one known application global, and no result bytes from that
  target are returned through the analyzer result.
* No general bound on host-allocated `next_data_batch` lengths or outside
  buffers; only the untagged-to-protected domain case is exercised here. The
  check intentionally permits outside host pointers and the application's
  read-only COMPAT range; those are not tested by this control.
* C14 is the same copy through the sealed provider before its decrypt. No
  additional sealed-data or key-manager attack is claimed.
* No SGX hardware, full toolkit/deployment, key-manager stress, repeated-session,
  concurrency, timing or performance result. Native/SDK SIM evidence is separate
  from hardware.
* The target object is an application global in a protected region. The control
  demonstrates the domain check, not exact object bounds for every application
  allocation; see the C15 record for a slot-granularity counterexample.

## Reproduction

```sh
# normal selected integration (four configurations)
python3 apps/yeez/execute.py --profile BASELINE
python3 apps/yeez/execute.py --profile RADIX_ONLY
python3 apps/yeez/execute.py --profile MAC27
python3 apps/yeez/execute.py --profile MAC27 --high

# C13/C14 hostile control (builds its own signed images under build/yeez)
python3 apps/yeez/hostile_control.py \
  --out build/yeez/c13-hostile-v1 \
  --evidence evidence/2026-10-24-yeez-c13-c14-hostile.json
```

`hostile_control.py --config PROFILE-low|PROFILE-high --rebuild` selects one row.
The signed output directories are separate from the normal integration evidence.
The machine-readable record retains unsigned/signed hashes, host hashes, gdb
scripts, logs and excerpts.

## Identities

* Pinned upstream: `YeeZTech/YeeZ-Privacy-Computing` revision
  `d6eadeca03d04848ea462ab2602f155219b6d3c3`; recovered source under
  `build/yeez-blocker-assessment-final/source/`.
* Selected analyzer: `example/multi_personlist/first_match/enclave/eparser.cpp`;
  key manager: `ypc/keymgr/default/enclave/ekeymgr.cpp`.
* Unsigned analyzer/key-manager SHA-256:
  * BASELINE `7d207048ec21a5f4a0189e1fd5e3ab223b6ede81791699ae16eafa5dec4f8220` /
    `c6a6e021e8b8be571f27549e774dec2ea21fdf5feef9ed359e233bfe7209e7a2`
  * RADIX_ONLY `8f1a1f77104e1175dbdd4e82888d1fa314b15abb035b2b311c31c2564dad17a8` /
    `d205ea131df69fd96912b1cf1972d37eaad3afe6d6de7e970ce7d870b7c9eb30`
  * MAC27 `9271da61fc9f15947e37f5e4c8b9a3081fe0bce2d1dc70cb9b680be4ae109c0b` /
    `9f3e9449cc7db3b7a4ffe6829567cb0fb85fe392ba6584757047ea5aedf906d5`
* Per-row signed-image hashes and gdb logs are in
  [`2026-10-24-yeez-c13-c14-hostile.json`](2026-10-24-yeez-c13-c14-hostile.json).
