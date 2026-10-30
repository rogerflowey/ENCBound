# SGX-KMS C16 hostile-pointer protection control — 2026-10-23

**SDK SIM protection result for the selected C16 key use.** The integrated
SGX-KMS image reaches the unchanged `ecall_proc_ma` through a real
current-session RA/GCM prefix. This control keeps that prefix and changes only
the raw pointer copied through the original `[in] void **c_p_net_ctxt` slot.
BASELINE consumes a host-selected raw enclave key; RADIX_ONLY and MAC27 reject
the same key range in the checked GCM adapter before the SDK reads it. The
benign host-key control and the existing 103-ECALL functional fixture still
pass in every configuration.

This is the next stage identified by the
[benign C16 session](2026-10-23-sgx-kms-c16-session.md) and the
[C16 resolution proposal](2026-10-23-c16-trusted-import-resolution.md). It adds
no application, EDL, pointer-mechanism, protected-scope, trusted-role, backend
or target change. The signed images are reused byte-for-byte.

## Finding

The unchanged EDL keeps the shallow pointer slot:

```text
isv_enclave/isv_enclave.edl:81
public int ecall_proc_ma(..., [in] void **c_p_net_ctxt, ...);
```

`[in] void **` copies one pointer value into enclave marshaling storage. The
unchanged body reads it and takes the key field:

```text
source/isv_enclave.cpp:665
sp_db = (sp_db_item_t *)*c_p_net_ctxt;

source/isv_enclave.cpp:669
server_put_secret_data(sealed_nonse, sealed_sk_len,
    (uint8_t *) &sp_db->sk_key, sizeof(sp_db->sk_key), ...);

source/isv_enclave.cpp:673   (second outgoing payload, same key)
```

There is no outside-enclave, provenance or range check on the supplied
pointer. The first use of the resulting key address is the checked GCM adapter:

```text
apps/sgx-kms/adapters.c:87
const void *k = span(key, 16, ENCBOUND_ACCESS_READ);
```

The host therefore chooses the 16-byte key used to encrypt both C16 outgoing
payloads. The probe builds `target = key_address - offsetof(sp_db_item_t,
sk_key)`; the body's `&sp_db->sk_key` then names exactly `key_address`.

## Control design

`apps/sgx-kms/c16_control_host.c` reuses the independent OpenSSL RA peer from
the benign host: one fresh signed/MACed message-2 exchange, current-session
message-4 GCM input, matching identity fields and the original new-key branch.
It runs three modes:

| Mode | Key address supplied through `c_p_net_ctxt` | Expected |
| --- | --- | --- |
| `control` | host `sp_db_item_t`, key `0xb0..0xbf` | accepted in every profile |
| `cd-app` | image `g_secret` | BASELINE consumes; protected rejects |
| `cd-trusted` | pinned SDK RA item `sk_key` | BASELINE consumes; protected rejects |

`cd-app` names the application's own zero-initialized `g_secret` global. It is
in `.encbound.appbss` in BASELINE and `.encbound.globalbss` in the protected
images. The 8-byte object occupies a minimum-size 16-byte zeroed slot, so the
16-byte key read is all zero; the expected BASELINE ciphertext key is known
independently.

`cd-trusted` names the pinned SDK 2.26 `ra_db_item_t.sk_key`. The private packed
layout is checked by `c16_layout.c`:

```text
size=1088 mk_key=496 sk_key=512 smk_key=528
```

The runner fails if the pinned layout changes. The `g_ra_db` vector is in the
SDK `.bss`; its item allocation and `sk_key` lie in SDK-owned trusted memory,
outside application regions. Its `sk_key` is the current session SK also
derived by the independent RA peer. The BASELINE host verifies both outgoing
ciphertexts under that SK. This demonstrates that the unchanged body used the
trusted SDK key, not that an unknown secret was extracted: the RA peer already
knows the session SK.

Only `c_p_net_ctxt` changes. The message-2 signature/MAC, quote identity
fields, message-4 GCM tag, sealed-key generation, `client_put_secret_data`
check and both `server_put_secret_data` calls are the existing fixture path.
The complete `ecall_proc_ma` body remains byte-identical, with SHA-256
`2a1d517a10db55bf246a55e2ced0d78fede38519ec72e542b131b482bcdd1a6e`.

## Fresh SDK SIM results

The runner reuses and hash-checks the four signed images from
`build/sgx-kms/session-c16-2026-10-23`, compiles the control host against each
image's generated untrusted wrapper and runs every mode in a child process.
`SIGILL` is the terminal protection abort.

| Configuration | `control` | `cd-app` | `cd-trusted` |
| --- | --- | --- | --- |
| BASELINE `0x40000000` | return 0, nonce+key PASS | return 0, nonce+key PASS, key `0x40279964` | return 0, nonce+SK PASS, key `0x4027b280` |
| RADIX_ONLY `0x40000000` | return 0, nonce+key PASS | SIGILL (`-4`) | SIGILL (`-4`) |
| MAC27 `0x40000000` | return 0, nonce+key PASS | SIGILL (`-4`) | SIGILL (`-4`) |
| MAC27 `0x140000000` | return 0, nonce+key PASS | SIGILL (`-4`) | SIGILL (`-4`) |

BASELINE logs:

```text
{"mode":"control","status":0,"source":"host","target":"0x7ffc54aaafe0","key":"0x7ffc54aab080","nonce_verified":true,"server_key_ciphertext":"decrypted"}
{"mode":"cd-app","status":0,"source":"g_secret","target":"0x402798c4","key":"0x40279964","nonce_verified":true,"server_key_ciphertext":"decrypted"}
{"mode":"cd-trusted","status":0,"source":"ra_db.sk_key","target":"0x4027b1e0","key":"0x4027b280","nonce_verified":true,"server_key_ciphertext":"decrypted"}
```

The high-base protected rows use `0x140287018` / `0x14028af10` for the two
targets. Each successful hostile row decrypts and authenticates both the nonce
and the returned server-key ciphertext under the selected key; a wrong key
fails the GCM tag.

Protected rows print only their target descriptor and then terminate with
SIGILL; no result JSON is produced. Example:

```text
{"mode":"cd-app","stage":"target","source":"g_secret","target":"0x40286f78","key":"0x40287018"}
{"mode":"cd-trusted","stage":"target","source":"ra_db.sk_key","target":"0x4028ae70","key":"0x4028af10"}
```

## Attribution

Six fresh debugger traces cover both hostile modes in RADIX_ONLY, MAC27 and
high-base MAC27. Every trace stops at the same checked consumption site.
`code=3` is `ENCBOUND_ERR_POLICY`, the expected rejection for an unminted raw
pointer to PROTECTED or TRUSTED memory.

```text
encbound_abort (code=3) at sdk/platform_layout.c:459
#1 encbound_require (width=16, kind=1) at runtime/capability.c:186
#2 span (n=16, access=1) at apps/sgx-kms/adapters.c:33
#3 encbound_kms_encrypt (...) at apps/sgx-kms/adapters.c:87
#4 server_put_secret_data (..., plain_ra_key=0x40287018 <g_secret>, ...)
     at source/isv_enclave.cpp:521
#5 ecall_proc_ma (...) at source/isv_enclave.cpp:669
#6 sgx_ecall_proc_ma (...) at generated/enclave_t.c
```

For `cd-trusted`, the same stack has `plain_ra_key=0x4028af10` (the pinned RA
item's `sk_key`), and the high-base rows use `0x140287018` / `0x14028af10`.
The abort fires before `sgx_rijndael128GCM_encrypt`; the first outgoing payload
is never produced and the second call is unreachable. This is an
adapter-enforced rejection for these targets, not a later application access
check.

## Functional regression

The existing benign host was rerun from each signed image:

```text
SGX-KMS C16 BENIGN SIM PASS calls=103 independent_checks=27 valid_msg2=3 c16_success=6 c16_identity_reject=3 c16_tag_reject=3
```

All four configurations pass, including three fresh message-2 exchanges, six
successful C16 calls and the identity/bad-tag recovery sequence. The benign
host-key mode of the new control also passes in every configuration, so the
host-key path itself is not what the protected profiles reject.

## Scope and limits

* SDK SIM plus debugger attribution. No SGX hardware isolation, timing,
  arbitrary-address sweep or full deployment result is established.
* The host knows the enclave base and reads image `.symtab`; for `cd-trusted`
  it also reads the simulated process's mapped `g_ra_db` vector. These are test
  premises, not production address leaks.
* `cd-app` uses a zero-initialized application global, not a secret. It shows
  selection of a protected-global range as the GCM key.
* `cd-trusted` does not extract an unknown secret: the selected RA peer knows
  the session SK. It shows that an untagged raw pointer to the SDK's trusted RA
  key state is confined before the SDK reads or uses it.
* One 16-byte key range is selected per mode; the control does not claim every
  enclave address is reachable or that all application/trusted data is safe.
* Full original-host message-3/quote/IAS, PSE, Barbican deployment, hardware,
  resource exhaustion, cleanup and C17–C19 protection remain separate.
* No pointer mechanism, EDL declaration, protected scope, trusted boundary,
  backend or frozen target changed.

## Reproduction

From the repository root, first build the benign session if it is not present:

```sh
python3 apps/sgx-kms/run.py --build build/sgx-kms/session-c16-2026-10-23
python3 apps/sgx-kms/c16_protection.py \
  --build build/sgx-kms/session-c16-2026-10-23 --trace \
  --evidence evidence/2026-10-23-sgx-kms-c16-protection.json
```

Logs and per-row hosts are retained under `build/sgx-kms/c16-protection/`.
The machine-readable record is
[2026-10-23-sgx-kms-c16-protection.json](2026-10-23-sgx-kms-c16-protection.json).

## Identities

* Pinned upstream `cloud-security-research/sgx-kms` at
  `1c9d2d2df117845166196a1c3f6f2fb1b998e2c9`.
* Unchanged `ecall_proc_ma` body SHA-256
  `2a1d517a10db55bf246a55e2ced0d78fede38519ec72e542b131b482bcdd1a6e`.
* Signed images: BASELINE `36b40930…`, RADIX_ONLY `9dee3a83…`,
  MAC27 `03a81bf5…`, high-base MAC27 `85c9982f…` (full hashes in the JSON).
* Control host source `c16_control_host.c`, runner `c16_protection.py` and
  layout check `c16_layout.c` hashes are bound in the JSON.
