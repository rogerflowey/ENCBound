# Source provenance

Pinned upstream: `asonnino/sgx-wallet@8d15df13e1e37b95d233b3911b5e21ba32a8b962` (MIT). Source bodies and original host inputs are verified by `tools/check_wallet_pins.py`; the revision, license and source file pins are also in `config/paper-sources.json`. Upstream source and its original LICENSE are fetched under ignored `build/paper-sources/sgx-wallet/`.

The enclave source is compiled as C, with explicit bridge, serial host and checked SDK adapter integration. Local recipe/host code is retained from ENCBound-restart. Development signing keys are generated under `build/`. The current modified Intel generator is used. The selected three-profile SDK SIM evidence is part of the dated first-ten record; no new result is inferred from copying it.
