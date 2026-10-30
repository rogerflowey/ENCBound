#!/usr/bin/env python3
"""ENCBound object audit: verify an object's instrumentation domain.

The pass writes `__encbound_instrumented` into section `.encbound.audit`
containing the protection profile. An application/dependency object must carry
this marker with the expected profile; a trusted object (runtime, bootstrap,
SDK, generated bridge) must not carry it. This catches an application object
compiled without the pass, or a trusted object compiled through it.

Usage:
    encbound_inventory.py audit --object FILE --expect instrumented|trusted \
        [--profile MAC27]
    encbound_inventory.py section --object FILE
"""
import argparse
import struct
import sys

SECTION = ".encbound.audit"


def read_sections(path):
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:4] != b"\x7fELF":
        raise SystemExit(f"{path}: not an ELF file")
    if data[4] != 2:
        raise SystemExit(f"{path}: only 64-bit ELF is supported")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def header(index):
        base = e_shoff + index * e_shentsize
        name, _type, _flags, _addr, offset, size = struct.unpack_from(
            "<IIQQQQ", data, base
        )
        return name, offset, size

    _, strtab_off, strtab_size = header(e_shstrndx)
    strtab = data[strtab_off : strtab_off + strtab_size]
    sections = {}
    for index in range(e_shnum):
        name_off, offset, size = header(index)
        end = strtab.index(b"\x00", name_off)
        name = strtab[name_off:end].decode("utf-8", "replace")
        sections[name] = data[offset : offset + size]
    return sections


def get_marker(path):
    sections = read_sections(path)
    if SECTION not in sections:
        return None
    raw = sections[SECTION]
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def cmd_section(args):
    marker = get_marker(args.object)
    if marker is None:
        print(f"section {SECTION}: absent")
        return 1
    print(f"section {SECTION}: profile={marker}")
    return 0


def cmd_audit(args):
    marker = get_marker(args.object)
    if args.expect == "instrumented":
        if marker is None:
            print(f"FAIL {args.object}: expected instrumented, marker absent")
            return 1
        if args.profile and marker != args.profile:
            print(
                f"FAIL {args.object}: profile {marker!r} != expected "
                f"{args.profile!r}"
            )
            return 1
        print(f"OK   {args.object}: instrumented profile={marker or 'unknown'}")
        return 0
    if marker is not None:
        print(f"FAIL {args.object}: expected trusted, found marker {marker!r}")
        return 1
    print(f"OK   {args.object}: trusted (no marker)")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    section = sub.add_parser("section", help="print the audit marker")
    section.add_argument("--object", required=True)
    section.set_defaults(func=cmd_section)

    audit = sub.add_parser("audit", help="verify an object's domain")
    audit.add_argument("--object", required=True)
    audit.add_argument("--expect", choices=["instrumented", "trusted"],
                       required=True)
    audit.add_argument("--profile", default=None)
    audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
