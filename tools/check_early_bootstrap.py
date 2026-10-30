#!/usr/bin/env python3
"""Audit the x86-64 SDK's actual dynamic initializer array, in dispatch order.

Priority names alone cannot establish ordering when entries tie. Resolve the
array selected by DT_INIT_ARRAY/DT_INIT_ARRAYSZ, including RELATIVE relocations,
and require its first target to be the exact trusted bootstrap function.
"""
import argparse
import json
import struct
import subprocess
from pathlib import Path


def initializers(image):
    raw = Path(image).read_bytes()
    if raw[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', raw, 18)[0] != 62:
        raise ValueError('expected little-endian x86-64 ELF')
    phoff = struct.unpack_from('<Q', raw, 32)[0]
    entsize, count = struct.unpack_from('<HH', raw, 54)
    ph = [struct.unpack_from('<IIQQQQQQ', raw, phoff+i*entsize) for i in range(count)]

    def offset(address, size):
        matches = [p for p in ph if p[0] == 1 and p[3] <= address and
                   address+size <= p[3]+p[5]]
        if len(matches) != 1:
            raise ValueError('dynamic data is not uniquely file-backed')
        return matches[0][2]+address-matches[0][3]

    dynamic = [p for p in ph if p[0] == 2]
    if len(dynamic) != 1:
        raise ValueError('expected one PT_DYNAMIC')
    p = dynamic[0]
    tags = {}
    for pos in range(p[2], p[2]+p[5], 16):
        tag, value = struct.unpack_from('<QQ', raw, pos)
        if tag == 0:
            break
        if tag in (7, 8, 9, 17, 18, 25, 27, 35, 36):
            if tag in tags:
                raise ValueError('duplicate dynamic array/relocation tag')
            tags[tag] = value
    start, size = tags.get(25, 0), tags.get(27, 0)
    if tags.get(18, 0) or tags.get(35, 0):
        raise ValueError('unsupported REL/RELR dynamic relocations')
    if not start or not size or start % 8 or size % 8:
        raise ValueError('missing or malformed DT_INIT_ARRAY')
    pos = offset(start, size)
    targets = list(struct.unpack_from('<'+'Q'*(size//8), raw, pos))
    relocated = set()
    if tags.get(8, 0):
        if not tags.get(7) or tags.get(9) != 24 or tags[8] % 24:
            raise ValueError('unsupported dynamic RELA layout')
        pos = offset(tags[7], tags[8])
        for n in range(pos, pos+tags[8], 24):
            dst, info, addend = struct.unpack_from('<QQq', raw, n)
            if dst < start+size and dst+8 > start:
                if dst < start or (dst-start) % 8 or info != 8 or dst in relocated:
                    raise ValueError('unsupported/duplicate initializer relocation')
                targets[(dst-start)//8] = addend
                relocated.add(dst)
    # The pinned SDK applies ELF RELA, not REL/RELR, to these entries.
    return {'address': start, 'size': size, 'targets': targets}


def audit(image, symbol='encbound_early_bootstrap'):
    records = [l.split() for l in subprocess.check_output(
        ['nm', '--defined-only', str(image)], text=True).splitlines()]
    matches = [int(w[0], 16) for w in records if len(w) == 3 and
               w[1] in ('t', 'T') and w[2] == symbol]
    if len(matches) != 1:
        raise ValueError('expected one bootstrap function: '+symbol)
    result = initializers(image)
    if result['targets'][0] != matches[0]:
        raise ValueError('bootstrap is not the first dynamic initializer')
    if result['targets'].count(matches[0]) != 1:
        raise ValueError('bootstrap occurs more than once')
    result['symbol'] = symbol
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('--symbol', default='encbound_early_bootstrap')
    a = p.parse_args()
    print(json.dumps(audit(a.image, a.symbol), indent=2))
