# Selected tlibc source origin

Origin: Intel SGX SDK **2.26**, local pinned source tree
`/home/roger/project/TEE/ENCBound/.local/sgxbounds/intel-sgx-simulation-2.26/sdk/tlibc`.
[pins.json](pins.json) fixes SHA-256 identities for 10 implementation files and
nine private headers. The builder reads this tree without writing it and copies
only these files under this restart's build directory. The SDK headers/archives
are independently pinned by the existing SDK audit. The pass/driver records the
actual consumed header hashes for every object.

| Source units | Purpose |
| --- | --- |
| stdio/snprintf.c, vsnprintf.c, vfprintf.c, fvwrite.c | Bounded formatting entrypoints, format engine and buffer writes |
| gdtoa/dtoa.c, misc.c, dmisc.c, hdtoa.c | Decimal/hex double conversion and its arithmetic/cache helpers |
| locale/multibyte_citrus_none.c | SDK's existing single-byte wide conversion |
| gen/fpclassify.c | Scalar floating classification used by conversion |
| helpers.c (original restart code) | Instrumented C memchr; avoids assembly memchr |
| ../../libc/errno.c (original restart code) | One shared serial application errno provider, instrumented/placed as application code; SDK TLS remains private |

The original Berkeley BSD-3-Clause, Citrus BSD-2-Clause, David M. Gay/Lucent
permission and OpenBSD ISC notices remain in copied source/header files.
[LICENSES.txt](LICENSES.txt) retains their actual notices, including the Lucent
supporting-documentation notice. No sources are imported from the old ENCBound
implementation or a musl port. The fixture's layout check/configuration and
auditing pattern reuse the restart's existing STL service.

Explicit configuration changes, applied only to copied application sources:

1. Select gdtoa's upstream single-thread configuration; no SDK mutex state.
2. Omit the long-double-only `__hldtoa` body; retain the complete `__hdtoa` body.
3. Replace long-double format/positional retrieval paths with explicit errors,
   set the FILE error flag and propagate positional-table failures before use.
   This avoids unsupported ABI access and preserves cleanup.
4. Privately namespace every selected upstream/helper externally defined function **and data symbol**.
   Other memory accesses and allocation calls use normal compiler instrumentation.

The October 23 common errno provider replaces the earlier formatter-only cell.
Its two ABI symbols retain their common names across application libraries;
the application-only header overlay supplies the same environment to probes,
callers and definitions. This adds one original support object to the historical
10-unit-plus-helper configuration; no additional upstream code is copied.

Exact adaptation text and prepared-source hashes are retained per profile in
`build.json`. `%n` retains the SDK's intentional abort. This is a selected,
serial application-library configuration, not a complete libc rebuild.
