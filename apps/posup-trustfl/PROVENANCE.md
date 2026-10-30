# Origin and reuse

`prepare.py` extracts exact Git objects into disposable `build/` trees. It
retains every extracted file's SHA-256, the Git archive SHA-256, selected-body
hashes and prepared-input hashes. No upstream source is vendored here.

| Input | Revision / identity | License / use |
| --- | --- | --- |
| [thanghoang/POSUP](https://github.com/thanghoang/POSUP) | `9a6e181763535fd927bca1749cd804e5d77f2f73` | MIT, Copyright 2018 Thang Hoang; retain the pinned `LICENSE` in the extracted source. Required bodies and three globals from `Enclave/Enclave.cpp` / `Enclave.h`; `TYPE_ID` is the original `int`. |
| [zeyu-zh/TrustFL](https://github.com/zeyu-zh/TrustFL) | `9e05a7e160bbf4fa1e7a426767f69158ea89b22d` | Repository `LICENSE` is Apache-2.0; retain it in extracted source. Selected functions/globals from `Enclave/verify.cpp`, record definition from `verify.h`. |
| Intel SDK 2.26 `sdk/tlibc/stdlib/abs.c` | SHA-256 `9944dfff06f4776407cd08c09c6a57ece27581cf47d9b0c2a5342bdf50c4aa3c` | UC Regents BSD three-clause notice retained in original source and compiler dependency record. Private `app_posup_abs`, compiled through the pass in protected profiles. |
| Intel SDK libc++ | Existing `apps/libcxx/pins.json` and complete preparation manifest | Existing private source-recompiled configuration and source/license records in `apps/libcxx/README.md`. All 26 configured objects are rebuilt per POSUP row. |
| Internal build/audit/host scaffolding | `apps/go-consensus-usig`, `apps/conflow`, `apps/four_app_audit.py`, `apps/four_app_permissions.h` | Local project reuse; adapted to explicit required-entry inventories and independently checked outputs. |
| Checked entropy/HMAC services | Existing `apps/go-consensus-usig/adapters.c` | Trusted exact range-check contracts reused unchanged; source/dependency hashes enter the build record. Other unused adapter functions are discarded by section GC. |

The new host exercises the actual required bodies and pinned absolute-value
unit with independent set and OpenSSL oracles. `controls.py` supplies eight
negative provenance/audit tests. No reused raw application library is silently
made trusted, and no SDK archive is relabeled as application data.
