#!/usr/bin/env python3
"""Opt-in object-owned data placement; preserve flags, groups and NOBITS.

The build supplies application objects only. Final link ownership/permissions
must additionally pass audit_app_globals.py. Unknown allocated data fails closed.
"""
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def sections(path):
    # GNU readelf 2.46 truncates section names at 256 bytes even with -W.
    # Template construction-vtable names can exceed that limit; renaming and
    # checking them must use their complete identities.
    text = subprocess.check_output(['llvm-readelf-21', '-SW', str(path)], text=True)
    result = []
    for line in text.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+([A-Za-z]*)\s+\d+\s+\d+\s+(\d+)', line)
        if m:
            name, kind, address, size, flags, alignment = m.groups()
            result.append(dict(name=name, kind=kind, address=int(address, 16),
                               size=int(size, 16), flags=flags, alignment=int(alignment)))
    return result


def main():
    src, dst = map(Path, sys.argv[1:])
    if src.resolve() == dst.resolve():
        raise ValueError('placement requires a separate output path')
    symbols = subprocess.check_output(['nm', str(src)], text=True)
    if re.search(r'^\S+ C ', symbols, re.M):
        raise ValueError('COMMON is unsupported; compile with -fno-common')
    before = sections(src)
    mappings = {}
    for s in before:
        n = s['name']
        if 'A' not in s['flags']:
            continue
        if '__encbound_cxx_eh_v1' in symbols and (n.startswith('.gcc_except_table') or n in ('.data.DW.ref.encbound_eh_personality','.data.DW.ref.__gxx_personality_v0')):
            continue  # private compiler unwind tables/personality reference
        if n.startswith(('.init_array', '.fini_array')) and '__encbound_lifecycle_v1' in symbols:
            continue  # compiler-admitted startup metadata stays TRUSTED
        if 'T' in s['flags'] or n.startswith(('.init_array', '.fini_array', '.ctors', '.dtors')):
            raise ValueError('unsupported application section: ' + n)
        if 'X' in s['flags']:
            if not n.startswith('.text'):
                raise ValueError('unexpected executable section: ' + n)
            continue
        if n in ('.encbound.globalrw', '.encbound.globalbss', 'encbound_gcaps', 'encbound_gfix'):
            continue  # compiler-owned storage, verified by final global audit
        if n.startswith('.rodata') and 'W' not in s['flags']:
            target = '.encbound.appdata' + n
        elif n.startswith('.data.rel.ro') and s['kind'] == 'PROGBITS' and 'W' in s['flags']:
            target = '.encbound.apprelro' + n
        elif n.startswith('.data') and s['kind'] == 'PROGBITS' and 'W' in s['flags']:
            target = '.encbound.apprw' + n
        elif n.startswith('.bss') and s['kind'] == 'NOBITS' and 'W' in s['flags']:
            target = '.encbound.appbss' + n
        elif n in ('.encbound.audit', '.encbound.abi', '.eh_frame'):
            continue  # control metadata stays outside COMPAT
        else:
            raise ValueError('unclassified application section: ' + n)
        mappings[n] = target
    dst.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dst.parent) as tmp:
        out = Path(tmp)/'object.o'
        command = ['objcopy']
        for source, target in mappings.items():
            command += ['--rename-section', source + '=' + target]
        subprocess.run(command + [str(src), str(out)], check=True)
        after = {s['name']: s for s in sections(out)}
        for s in before:
            if s['name'] not in mappings:
                continue
            actual = after[mappings[s['name']]]
            for field in ('kind', 'size', 'flags', 'alignment'):
                if actual[field] != s[field]:
                    raise ValueError('section property changed: ' + field)
        out.replace(dst)
    record = {'input': str(src.resolve()), 'input_sha256': hashlib.sha256(src.read_bytes()).hexdigest(),
              'output_sha256': hashlib.sha256(dst.read_bytes()).hexdigest(), 'sections': mappings}
    Path(str(dst)+'.ownership.json').write_text(json.dumps(record, indent=2)+'\n')
    print('APP GLOBALS =>', dst)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as e:
        sys.exit('application data placement failed: ' + str(e))
