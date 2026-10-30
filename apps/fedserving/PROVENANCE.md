# Sources and licenses

Application origin: [H-W-Huang/FedServing](https://github.com/H-W-Huang/FedServing),
commit `da49236c4ae18cf3c9cdde5d8df6fd7505d442c0`.
[pins.json](pins.json) fixes the consumed C++, EDL, aggregator header and README.
No project LICENSE file was found at this revision. Application sources are
read from the checkout and prepared only under the ignored build directory;
they are not vendored in this recipe. The README and `prepared.json` describe
the bounded configuration and ordinary missing-return correction.

Private library origin: the pinned Intel SGX SDK 2.26 source tree's `sdk/tlibc`.
The formatter's [origin](../libc-format/PROVENANCE.md),
[notices](../libc-format/LICENSES.txt), source pins and serial configuration
continue to apply. [libc-pins.json](libc-pins.json) adds exactly eight units:
`math/e_exp.c`, `e_log.c`, `e_pow.c`, `e_sqrt.c`, `s_scalbn.c`, `s_copysign.c`,
`s_fabs.c`, and `gen/isnan.c`. The first seven retain the SunPro permission
notice; `isnan.c` retains the OpenBSD ISC notice. The copied files preserve
their notices, also reproduced in [LICENSES.txt](LICENSES.txt). The builder
privately namespaces these definitions and restores the private `__isnan` name
after its upstream macro undefinition. Consumed headers are recorded by hash
for every compiled unit.

The host, oracle, audit and build scripts are restart integration code. They
reuse the restart's existing selected-libc builder, ownership audit, bridge
generator, checked runtime, metadata tooling and loaded-permission probe.
Neither the old ENCBound implementation nor another libc/backend is imported.
