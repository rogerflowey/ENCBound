#!/usr/bin/env python3
"""Enforce the pinned Intel SGX SDK correspondence for step 2.

Checks three things:
  1. installed SDK binaries match their recorded SHA-256;
  2. pinned internal layout headers match their recorded SHA-256;
  3. the installed libsgx_trts_sim.a g_global_data object size equals the
     sizeof(global_data_t) derived from those pinned headers.

The third check is the header/binary correspondence the design requires: a
version string match alone is not enough. Exits non-zero on any mismatch.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

GLOBAL_DATA_SIZE = 1768  # sizeof(global_data_t) from the pinned headers

# Optional lifecycle builds link this exact SDK C++ archive for guard routines.
# Keep it separate from the four-archive historical experiment closure.
CXX_GUARD_ARCHIVE_SHA256 = '50731a201df955b9fab2f4b6292c5c9004bcfc089fa7af4ad956a97bb8fa1a21'

SDK_BINARIES = {
    "bin/x64/sgx_edger8r":
        "3e7bc8e6a45f84029adff0f79273cb5c95fa116cfef0af9c43b6193b5b056ca5",
    "bin/x64/sgx_sign":
        "29667e1842af96603f4e2ed593bbed1c7379a4908fddd312e431a56a7483a290",
    # The archives and shared library the evaluated wallet links, resolved by the
    # linker on the trusted and untrusted link lines. Pinning the archives is
    # not the same as the name-only inventory audit; a rebuilt or substituted
    # archive must fail here (docs/legacy/steps/10-evaluation-campaign.md E0.5).
    "lib64/libsgx_trts_sim.a":
        "fd2e9a148f59e73e6968aa99c96dd5b286460d6ab76648095c0906ea2312bf73",
    "lib64/libsgx_tstdc.a":
        "61023a3d31cdb630150752feadba1da6165290d598e2ea530f2a0d633fa5bf1f",
    "lib64/libsgx_tcrypto.a":
        "cbb7ed1d7685e5c98dbf6b7560488bde889a1ad408c6777d0303843a52639cec",
    "lib64/libsgx_tservice_sim.a":
        "b53f3e15dc543515ee2f595d389a1f62724fafdc7c98d42aabc0ce61c7462f70",
    "lib64/libsgx_urts_sim.so":
        "0948df2cf8a88e030f9d2d464647360086cd8067374066c2be8b96e443c6edde",
}

PINNED_HEADERS = {
    "common/inc/internal/global_data.h":
        "1e675362c5f59cf9c74b22d2ae3c85e6a43f84fa704fc97c2843b1fe149a28c7",
    "common/inc/internal/thread_data.h":
        "4cbfda0e043529d24e84ea531148acd339277a73a0e12aabaa1f0d1ac70949de",
    "common/inc/internal/metadata.h":
        "46519b41013f9e13953719d45aa1433e8da9fb3134e0c3666af835adf07ca152",
}

# The modified-bridge driver consumes this SDK EDL as a trusted, non-application
# import; its exact identity is enforced again in boundary-interface.json.
SDK_EDL = {
    "include/sgx_tstdc.edl":
        "b7cd049fa088a3f8223fb9a9e71d791107c2886019ba332d042c34402ee0554e",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_hashes(base, mapping, errors):
    for name, expected in mapping.items():
        path = Path(base) / name
        if not path.exists():
            errors.append(f"missing: {path}")
        elif digest(path) != expected:
            errors.append(f"changed: {path}")


def check_global_data_size(archive, errors):
    result = subprocess.run(["readelf", "-sW", str(archive)], text=True,
                            stdout=subprocess.PIPE)
    found = False
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[-1] == "g_global_data" and \
                fields[3] == "OBJECT":
            found = True
            if int(fields[2]) != GLOBAL_DATA_SIZE:
                errors.append(
                    f"g_global_data size {fields[2]} != pinned "
                    f"{GLOBAL_DATA_SIZE}")
    if not found:
        errors.append("g_global_data object not found in installed tRTS")


def resolved_archives(link_map):
    """The .a inputs the linker actually resolved, as full paths, from a map.

    This is the set of archives bound into the emitted image, independent of
    the default SDK directory or any caller override of the search path.
    """
    seen = set()
    for line in Path(link_map).read_text().splitlines():
        if not line.startswith("LOAD "):
            continue
        target = line.split(maxsplit=1)[1]
        target = target.split(" (", 1)[0].split("(", 1)[0].strip()
        if target.endswith(".a"):
            seen.add(target)
    return sorted(seen)


def check_link_map(link_map, errors, *, additional=None):
    """Bind the pin hashes to the archives the link actually used.

    A same-named archive reached through an overridden search path fails here,
    because the hash is taken from the resolved link input, not a default path.
    """
    link_map = Path(link_map)
    if not link_map.exists():
        errors.append(f"missing link map: {link_map}")
        return
    resolved = resolved_archives(link_map)
    if not resolved:
        errors.append(f"no SDK archives resolved in link map: {link_map}")
        return
    binaries = {**SDK_BINARIES, **(additional or {})}
    expected_names = {Path(n).name for n in binaries if n.endswith('.a')}
    if {Path(n).name for n in resolved} != expected_names:
        errors.append(f"linked SDK archive inventory differs from pins: {link_map}")
    for target in resolved:
        name = Path(target).name
        expected = binaries.get("lib64/" + name)
        path = Path(target)
        if not path.is_absolute():
            # The map does not identify the link working directory. The
            # selected recipes use absolute paths; never guess another base.
            errors.append(f"linked archive path must be absolute: {target}")
            continue
        if not path.exists():
            errors.append(f"linked archive missing: {path}")
        elif expected is None:
            errors.append(f"unpinned archive linked: {path}")
        elif digest(path) != expected:
            errors.append(f"linked archive hash mismatch: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", required=True)
    parser.add_argument("--pinned", required=True)
    parser.add_argument('--sdk-ecalls', action='store_true',
                        help='include the exact SDK ECALL EDL/archive contract pins')
    parser.add_argument(
        "--link-map", action="append", default=[], type=Path,
        help="linker map(s) whose resolved .a inputs must match the pins")
    args = parser.parse_args()

    errors = []
    check_hashes(args.sdk, SDK_BINARIES, errors)
    check_hashes(args.sdk, SDK_EDL, errors)
    additional = {}
    if args.sdk_ecalls:
        contracts = json.loads((Path(__file__).resolve().parent/'edger8r/sdk-ecalls.json').read_text())
        for name, contract in contracts.items():
            check_hashes(args.sdk, {'include/'+name: contract['sha256']}, errors)
            additional['lib64/'+contract['archive']] = contract['archive_sha256']
        check_hashes(args.sdk, additional, errors)
    check_hashes(args.pinned, PINNED_HEADERS, errors)
    archive = Path(args.sdk) / "lib64/libsgx_trts_sim.a"
    if archive.exists():
        check_global_data_size(archive, errors)
    else:
        errors.append(f"missing: {archive}")
    for link_map in args.link_map:
        check_link_map(link_map, errors, additional=additional)

    if errors:
        for error in errors:
            sys.stderr.write("sdk-pins: " + error + "\n")
        return 1
    print("sdk-pins: OK "
          "(edger8r, signer, trts_sim, tstdc, tcrypto, tservice_sim, urts_sim, "
          "sgx_tstdc.edl, internal headers, g_global_data size)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
