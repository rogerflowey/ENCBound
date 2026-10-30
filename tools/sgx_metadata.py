#!/usr/bin/env python3
"""Read and check the signed Intel SGX enclave's .note.sgxmeta layout.

This is the static side of the Step 2 correspondence check: the signer's own
record of the enclosing range and layout entries, parsed from the signed
binary and compared with the expected configuration and, optionally, the
runtime layout reported by the trusted probe.

The .note.sgxmeta field offsets are pinned to Intel SGX SDK 2.26 and are the
same small understood component the previous project used; they are re-derived
and checked here rather than assumed.

Subcommands:
  show            print the parsed metadata
  required        print the derived power-of-two extent (hex)
  render-config   write a signer config from a template with base/size filled
  verify          check metadata (and optional runtime log) against base/size
"""
import argparse
import struct
import sys
from pathlib import Path

SGX_META_MAGIC = 0x86A80294635D0E4C
NOTE_HEADER_SIZE = 0  # metadata starts at the magic; parsed from there
META_VERSION_OFF = 8
META_ENCLAVE_SIZE_OFF = 40
# The layout and elrange directives live after the fixed metadata structure.
META_LAYOUT_DESC_OFF = 64 + 1808 + 8
META_ELRANGE_DESC_OFF = 64 + 1808 + 16
LAYOUT_ENTRY = "<HHIQIIQ"  # id, attributes, page_count, rva, content_size,
                           # content_offset, si_flags
LAYOUT_ENTRY_SIZE = 32
PAGE_SIZE = 4096
RESERVED_IDS = (20, 21, 22)
MAX_ELRANGE = 0x40000000
META_STRUCT_END = 1808 + 64


def parse(signed):
    raw = Path(signed).read_bytes()
    if raw[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"{signed}: not a 64-bit little-endian ELF")
    section_offset = struct.unpack_from("<Q", raw, 40)[0]
    entry_size, count, strings_index = struct.unpack_from("<HHH", raw, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw,
                                   section_offset + i * entry_size)
                for i in range(count)]
    strings = sections[strings_index]
    names = raw[strings[4]:strings[4] + strings[5]]
    notes = [s for s in sections
             if names[s[0]:].split(b"\0", 1)[0] == b".note.sgxmeta"]
    if len(notes) != 1:
        raise ValueError("expected exactly one .note.sgxmeta section")
    note = raw[notes[0][4]:notes[0][4] + notes[0][5]]
    magic = struct.pack("<Q", SGX_META_MAGIC)
    metadata = note[note.index(magic):]
    if len(metadata) < META_STRUCT_END:
        raise ValueError("truncated .note.sgxmeta")
    version = struct.unpack_from("<Q", metadata, META_VERSION_OFF)[0]
    enclave_size = struct.unpack_from("<Q", metadata, META_ENCLAVE_SIZE_OFF)[0]
    lay_off, lay_sz = struct.unpack_from("<II", metadata, META_LAYOUT_DESC_OFF)
    elr_off, elr_sz = struct.unpack_from("<II", metadata, META_ELRANGE_DESC_OFF)
    if elr_sz != 24:
        raise ValueError("unexpected ELRANGE directive size")
    layouts = []
    for p in range(lay_off, lay_off + lay_sz, LAYOUT_ENTRY_SIZE):
        e = struct.unpack_from(LAYOUT_ENTRY, metadata, p)
        layouts.append({"id": e[0], "attributes": e[1],
                        "page_count": e[2], "rva": e[3],
                        "end": e[3] + e[2] * PAGE_SIZE})
    image, start, size = struct.unpack_from("<QQQ", metadata, elr_off)
    return {
        "version": version,
        "enclave_size": enclave_size,
        "elrange": {"image": image, "start": start, "size": size},
        "layouts": layouts,
    }


def layout_end(info):
    return max((e["end"] for e in info["layouts"]), default=0)


def reserved_end(info):
    ends = [e["end"] for e in info["layouts"] if e["id"] in RESERVED_IDS]
    return max(ends, default=0)


def next_power_of_two(value):
    if value <= 1:
        return 1
    return 1 << (value - 1).bit_length()


def required_extent(info):
    required = max(layout_end(info), reserved_end(info))
    return next_power_of_two(required)


def cmd_show(args):
    info = parse(args.signed)
    print(f"metadata version : {info['version']:#x}")
    print(f"enclave_size     : {info['enclave_size']:#x}")
    elr = info["elrange"]
    print(f"elrange image    : {elr['image']:#x}")
    print(f"elrange start    : {elr['start']:#x}")
    print(f"elrange size     : {elr['size']:#x}")
    for e in info["layouts"]:
        print(f"layout id={e['id']:<3} rva={e['rva']:#x} "
              f"pages={e['page_count']} end={e['end']:#x}")
    print(f"layout_end       : {layout_end(info):#x}")
    print(f"required_extent  : {required_extent(info):#x}")
    return 0


def cmd_required(args):
    info = parse(args.signed)
    extent = required_extent(info)
    if extent > MAX_ELRANGE:
        sys.stderr.write(f"required extent {extent:#x} exceeds max "
                         f"{MAX_ELRANGE:#x}\n")
        return 1
    print(f"{extent:#x}")
    return 0


def cmd_render_config(args):
    text = Path(args.template).read_text()
    text = text.replace("@ENCLAVE_BASE@", f"{int(args.base, 0):#x}")
    text = text.replace("@ELRANGE_SIZE@", f"{int(args.size, 0):#x}")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text)
    return 0


def parse_probe_log(path):
    base = None
    size = None
    for line in Path(path).read_text().splitlines():
        if "base=" not in line or "size=" not in line:
            continue
        fields = dict(part.split("=", 1) for part in line.split()
                      if "=" in part)
        base = int(fields["base"], 0)
        size = int(fields["size"], 0)
        break
    return base, size


def cmd_verify(args):
    info = parse(args.signed)
    expected_base = int(args.base, 0)
    expected_size = int(args.size, 0)
    errors = []
    elr = info["elrange"]
    if elr["image"] != expected_base or elr["start"] != expected_base:
        errors.append(f"elrange base {elr['image']:#x}/{elr['start']:#x} != "
                      f"{expected_base:#x}")
    if elr["size"] != expected_size:
        errors.append(f"elrange size {elr['size']:#x} != {expected_size:#x}")
    if info["enclave_size"] != expected_size:
        errors.append(f"enclave_size {info['enclave_size']:#x} != "
                      f"{expected_size:#x}")
    for e in info["layouts"]:
        if e["end"] > expected_size:
            errors.append(f"layout id={e['id']} end {e['end']:#x} exceeds "
                          f"{expected_size:#x}")
    if required_extent(info) > expected_size:
        errors.append("derived required extent exceeds the signed extent")
    if args.runtime_log:
        rb, rs = parse_probe_log(args.runtime_log)
        if rb != expected_base or rs != expected_size:
            errors.append(f"runtime base/size {rb:#x}/{rs:#x} != signed "
                          f"{expected_base:#x}/{expected_size:#x}")
    if errors:
        for error in errors:
            sys.stderr.write("metadata: " + error + "\n")
        return 1
    print(f"metadata: OK base={expected_base:#x} size={expected_size:#x} "
          f"layouts={len(info['layouts'])}")
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("show")
    p.add_argument("--signed", required=True)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("required")
    p.add_argument("--signed", required=True)
    p.set_defaults(func=cmd_required)

    p = sub.add_parser("render-config")
    p.add_argument("--template", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--size", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render_config)

    p = sub.add_parser("verify")
    p.add_argument("--signed", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--size", required=True)
    p.add_argument("--runtime-log", default=None)
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
