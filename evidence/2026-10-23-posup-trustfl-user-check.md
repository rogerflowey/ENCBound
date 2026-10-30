# POSUP and TrustFL direct `[user_check]` pointer forgery — 2026-10-23

This record adds direct confused-deputy controls to the two bounded required-ECALL
integrations. It uses the unchanged upstream ECALL bodies and the existing matched
SDK SIM configurations. The functional workloads and the forgery controls are kept
separate; no EDL declaration, application body, ENCBound mechanism, protected scope,
trusted boundary, backend or frozen target changed.

## Finding

Both applications annotate their ECALL pointers `[user_check]`, which passes the
host-chosen raw pointer with no bridge copy, length, null, canonical or
outside-enclave check. Neither selected body calls `sgx_is_outside_enclave` or
validates a range.

```text
POSUP Enclave/Enclave.edl:18
public void ecall_getPathID([user_check] TYPE_ID* output);
POSUP Enclave/Enclave.edl:48
public void ecall_setFileIDs([user_check]unsigned char* fid_arr, int num_fileIDs);

TrustFL Enclave/Enclave.edl:17
public int ecall_data_preprocess([user_check] unsigned char* p_datau,
    unsigned int data_length, [user_check] unsigned char* p_labelu,
    unsigned int label_length, unsigned long p_training_hmacu);
```

POSUP stores a scalar and reads an array through the caller-chosen address:

```text
prepared/Enclave.cpp:10   *output = pathID;                 (upstream :931)
prepared/Enclave.cpp:19   memcpy(&tmp, &fid_arr[i * 4], 4);  (upstream :1686)
```

The store writes one `TYPE_ID` (`pathID`, zero in the selected subset). The loop
performs `num_fileIDs` four-byte reads from the host-chosen address and inserts
their absolute values into the application-owned `std::set`.

TrustFL reads its own memory as training data and writes HMAC output through two
more caller-chosen addresses:

```text
prepared/Enclave.cpp:40   memcpy(p_data_label, p_datau, rows*columns);  (upstream :100)
prepared/Enclave.cpp:41   p_data_label[rows*columns] = *p_labelu;      (upstream :101)
prepared/Enclave.cpp:45   p_hmacu[i] = temp;                           (upstream :105)
```

The loop is fixed at 60,000 records of 28x28 bytes, so naming an enclave address
at `p_datau` makes the enclave read at most 47,040,000 bytes of its own memory;
naming one at `p_labelu` reads 60,000 label bytes; naming one at
`p_training_hmacu` writes 1,920,000 bytes of HMACs there. With the upstream
zero-initialized key (before `ecall_init`) the host can independently compute
every expected HMAC.

## Control design and targets

`apps/posup-trustfl/confused_deputy_host.c` loads the unchanged signed image and
reuses the saved row's generated ECALL wrappers. It resolves targets from the
image's own section table or the loaded mapping table and checks them against
`/proc/self/maps`; no fixed scratch offset is assumed.

| Application | Mode | Raw pointer | Access |
| --- | --- | --- | --- |
| POSUP | `cd-read` | `.data+0x10` | `ecall_setFileIDs` reads two words from the image; the test-only copied-output ECALL returns the application set |
| POSUP | `cd-write` | `.data+0x10` | `ecall_getPathID` stores `pathID` over the first word |
| TrustFL | `cd-read` | `.text` | 60,000 label bytes are read from the image; every HMAC is checked |
| TrustFL | `cd-write` | largest loaded read-write span in the enclave extent (reserved memory) | 60,000 HMACs / 1,920,000 bytes are written into enclave memory |
| TrustFL | `cd-read-data` | `.text` | the training-data loop reads image bytes and faults at the mapped-image boundary; the child fault is isolated and the stable read-only prefix is byte-verified |

`.data+0x10` skips the SDK's `g_is_first_ecall` flag and identifies stable
version-string words. The TrustFL label and training-data reads use image `.text`
so that the bytes do not change during the call. The direct host reads used to
check the BASELINE store are SDK SIM observations.

Run:

```sh
python3 apps/posup-trustfl/confused_deputy.py --trace \
    --evidence evidence/2026-10-23-posup-trustfl-user-check.json
```

## Fresh direct SDK SIM results

| Configuration | POSUP `control` | POSUP `cd-read` | POSUP `cd-write` | TrustFL `control` | TrustFL `cd-read` | TrustFL `cd-write` | TrustFL `cd-read-data` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| BASELINE `0x40000000` | PASS | PASS, 2 words | PASS, word `1` → `0` | PASS | PASS, 60,000 labels | PASS, 1,920,000 bytes | PASS, 285 records / 223,440 bytes, child SIGSEGV |
| RADIX_ONLY `0x40000000` | PASS | SIGILL (`-4`) | SIGILL (`-4`) | PASS | SIGILL (`-4`) | SIGILL (`-4`) | SIGILL (`-4`) |
| MAC27 `0x40000000` | PASS | SIGILL (`-4`) | SIGILL (`-4`) | PASS | SIGILL (`-4`) | SIGILL (`-4`) | SIGILL (`-4`) |
| MAC27 `0x140000000` | PASS | SIGILL (`-4`) | SIGILL (`-4`) | PASS | SIGILL (`-4`) | SIGILL (`-4`) | SIGILL (`-4`) |

BASELINE logs:

```text
{"mode":"control","status":0,"getPathID":0,"words":1,"readback":"PASS"}
{"mode":"cd-read","status":0,"target":"0x40030010","words":"1146377044,1599620947","oracle":"1146377044,1599620947","readback":"PASS"}
{"mode":"cd-write","status":0,"target":"0x40030010","before":1599620947,"after":0,"neighbor":1146377044,"write":"PASS"}
```

```text
{"mode":"control","status":0,"records":60000,"macs":"PASS"}
{"mode":"cd-read","status":0,"target":"0x40001040","label_bytes":60000,"records":60000,"macs":"PASS"}
{"mode":"cd-write","status":0,"target":"0x4219c400","bytes":1920000,"records":60000,"macs":"PASS"}
{"mode":"cd-read-data","status":0,"target":"0x40001040","verified_records":285,"read_bytes":223440,"child_signal":11,"macs":"PASS"}
```

The POSUP `cd-read` result is the application set's sorted absolute values; the
host recomputed the same pair from the loaded `.data` words. The `cd-write` result
shows the first word changing from `1599620947` to `pathID` (`0`) with the
neighbouring word unchanged. TrustFL verified every one of the 60,000 HMACs
against independent OpenSSL HMACs of the host records and the enclave-resident
label bytes, and every one of the 60,000 HMACs written into the enclave span
against the same oracle. In `cd-read-data` the first 285 complete 784-byte records (223,440 bytes of
image `.text`) are byte-verified; the fixed 47 MB loop then continued past them
and ran off the mapped image, so the child receives SIGSEGV.

The protected `cd` rows produce no JSON result and terminate with SIGILL; the
`cd-read-data` child signal is re-raised by the parent.

## Attribution

Fresh debugger attribution for RADIX_ONLY, MAC27 and high-base MAC27 (`15`
traces). `code=3` is `ENCBOUND_ERR_POLICY`, the expected rejection for an
unminted raw enclave pointer.

```text
POSUP cd-read, RADIX_ONLY:
encbound_abort (code=3) at sdk/platform_layout.c:459
#1 encbound_require (width=4, kind=1) at runtime/capability.c:186
#2 encbound_memcpy (src=0x40044010 <sgx_tcxx_version>, n=4)
      at runtime/adapters.c:28
#3 ecall_setFileIDs (fid_arr=0x40044010 <sgx_tcxx_version>, num_fileIDs=2)
      at prepared/Enclave.cpp:19

POSUP cd-write, MAC27:
#1 encbound_require (...)
#2 ecall_getPathID (output=0x40044010 <sgx_tcxx_version>)
      at prepared/Enclave.cpp:10
```

```text
TrustFL cd-read, MAC27:
#1 encbound_require (...) at runtime/capability.c:186
#2 ecall_data_preprocess (p_labelu=0x40001038) at prepared/Enclave.cpp:41

TrustFL cd-write, MAC27:
#1 encbound_require (...) at runtime/capability.c:186
#2 ecall_data_preprocess (p_training_hmacu=1109005312)
      at prepared/Enclave.cpp:45

TrustFL cd-read-data, MAC27:
#5 encbound_abort (code=3)
#7 encbound_memcpy (src=0x40001040, n=784) at runtime/adapters.c:28
#8 ecall_data_preprocess (p_datau=0x40001040) at prepared/Enclave.cpp:40
```

The high-base rows are identical with `0x140...` addresses
(`0x140044010` for the POSUP `.data` target and `0x140001040` for the TrustFL
`.text` target). The abort fires at the first raw enclave access; the write at
`:45` and the store at `:10` are never reached in the protected profiles.

The [machine record](2026-10-23-posup-trustfl-user-check.json) binds the control
source and runner hashes, the eight signed row identities and prepared bodies,
and the 15 trace and run logs.

## Functional regression

All four configurations of both applications still pass the saved functional
host unchanged: POSUP `{"result":"PASS","calls":54,"comparisons":234}` and
TrustFL `{"result":"PASS","calls":5,"comparisons":5820000}`. The control modes
above use host buffers and pass in every row as well.

## Scope and limits

* SDK SIM plus SDK debugger attribution. No SGX hardware, timing, secret
  extraction, arbitrary-address sweep, unbounded write or code execution is
  claimed.
* The host knows the enclave base and image layout in SIM, as a loader does.
  This is a demonstration premise, not a production address leak.
* POSUP's write primitive stores `pathID` (`0`) only. Its read primitive returns
  absolute values into an application set; it is not a byte-exact copy. The
  unselected ORAM operations that assign other `pathID` values are still outside
  the integration.
* TrustFL's read primitive returns HMACs of enclave memory, not the plaintext
  bytes: with the known pre-init zero key this is an equality/verification
  oracle, not a general decryption of enclave memory. The 47 MB training-data
  read faults at the mapped-image boundary rather than completing, and the
  verified prefix is the stable read-only image.
* The write targets are one `.data` word, one 1,920,000-byte reserved-memory
  span and the image `.text`; the controls do not claim every enclave address is
  writable or that all bytes of the span are live application state.
* The `[user_check]` host buffers in the functional workloads remain host
  memory. No full-application, hardware or general vulnerability-prevention
  result follows.
