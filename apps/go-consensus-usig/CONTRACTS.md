# USIG SDK boundary contracts

These are application-specific trusted adapters following step 5, not changes
to the pointer mechanism or SDK/application ownership. They use the pinned
Intel SDK 2.26 IPP `libsgx_tcrypto.a`; SGXSSL is not interchangeable. The source
pins, archive identity, exact mapping inventory and native tests are recorded
with the build. All service results preserve SDK status. Geometry/policy/tag
failures terminate through `encbound_require`; no raw application fallback.

| Service | Application memory read / written | Other rules |
| --- | --- | --- |
| ECC open | Write one complete handle cell (8 bytes). | NULL returns INVALID_PARAMETER. Four private live context slots; exhaustion returns OUT_OF_MEMORY without opening another context. SDK pointer stays in trusted static storage; application gets integer token 1–4. A failed SDK open leaves caller cell untouched. |
| ECC close | None. | Validate token/live slot before SDK call. Successful close clears the trusted slot. Invalid, closed or forged raw SDK addresses return INVALID_PARAMETER. Token reuse is not temporal safety. |
| ECDSA sign | Read `data_size` bytes and 32-byte private key; write 64-byte signature. | Validate live token and SDK NULL/zero parameter rules first. All buffers checked before raw call. SDK context pointer comes only from private table. No retained application pointers or callbacks. SDK signs SHA256(data), with little-endian P-256 key/signature limbs. |
| HMAC-SHA256 message | Read positive signed `src_len` and `key_len`; write positive signed `mac_len`. | Preserve pinned SDK NULL/nonpositive errors without dereference. Validate all three ranges, including the full error-cleanup destination: IPP failure clears `mac_len` bytes. Truncated MACs/error statuses follow IPP, not a new application restriction. No handle/retention/callback. |
| Random | Write `length` bytes. | NULL/zero returns INVALID_PARAMETER. Used by the supplied missing crypto helper; no raw SDK pointer returned. |

Original five ECALL declarations and the print OCALL stay intact. EDL record
metadata identifies `sgx_ec256_private_t`; generated value adapters are compiled
and placed as application code. The private formatter supplies `vsnprintf`, so
the original `debug` and print buffer accesses remain instrumented.

Origin: ECC token handling adapts this restart's
`apps/sgx-enclave-protocol/adapters.c`; close handling follows
`apps/tpdv/adapters.c`. The missing application `crypto_verify_32` body uses the
public-domain DJB reference algorithm retained in
`apps/sk-sgx/upstream/verify.c`; `randombytes` is a new small application wrapper
around SGX random generation. Neither is an SDK/runtime trust promotion.
