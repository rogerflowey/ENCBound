#!/usr/bin/env python3
"""Trace a compiler-inserted crypto access check in one protected SDK SIM image.

Adapted from apps/fedserving/trace.py (internal project origin). This observes
a successful tagged access and its raw conversion; it is not an attack result.
"""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from probe import HERE, SDK, sha
from audit import audit


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build', type=Path, required=True)
    args = ap.parse_args()
    out = args.build.resolve()
    audit(out)
    r = json.loads((out/'build.json').read_text())
    assert r['profile'] in ('RADIX_ONLY', 'MAC27')
    base = int(r['base'], 16)
    image = Path(r['image'])
    sections = subprocess.check_output(['readelf', '-SW', image], text=True)
    rva = int(re.search(r'\]\s+\.text\s+PROGBITS\s+(\S+)', sections)[1], 16)
    line = next(i for i,s in enumerate((HERE/'host.c').read_text().splitlines(), 1)
                if s.strip().startswith('four_app_permissions('))
    command = out/'access.gdb'
    command.write_text(f'''set pagination off
set confirm off
break {HERE/'host.c'}:{line}
run
add-symbol-file {image} {base+rva:#x}
tbreak crypto_sign_ed25519_ref_fe25519_add
continue
tbreak encbound_require
continue
printf "SK_ACCESS capability=0x%lx width=%lu kind=%d\\n", capability, width, kind
bt 10
finish
printf "SK_RAW address=0x%lx\\n", $rax
disable
continue
''')
    cmd = ['gdb', '-q', '-batch', '-x', str(command), '--args', r['host']]
    result = subprocess.run(cmd, cwd=image.parent, capture_output=True, text=True, timeout=120,
        env=dict(os.environ, LD_LIBRARY_PATH=str(SDK/'lib64'), ENCBOUND_TEST_BASE=r['base']))
    text = result.stdout + result.stderr
    log = out/'access.log'
    log.write_text(text)
    match = re.search(r'^SK_ACCESS capability=(0x[0-9a-f]+) width=(\d+) kind=(\d+)$', text, re.M)
    raw = re.search(r'^SK_RAW address=(0x[0-9a-f]+)$', text, re.M)
    assert not result.returncode and match and raw and 'exited normally' in text, str(log)
    assert 'received signal' not in text and 'crypto_sign_ed25519_ref_fe25519_add (' in text
    cap, width, kind = [int(x,0) for x in match.groups()]
    address = int(raw[1], 16)
    assert 1 <= cap >> 59 <= 30 and address == base+(cap & 0xffffffff)
    assert width == 4 and kind == 1
    assert 'PASS ecalls=68 verified_signatures=21 provider=original-v4 max_application=4096' in text
    record = dict(profile=r['profile'], base=r['base'], mode='SDK SIM', command=cmd,
                  capability=hex(cap), raw=hex(address), width=width, kind=kind,
                  enforcement='compiler-inserted check in upstream fe25519_add; successful access',
                  log=str(log), log_sha256=sha(log), signed_sha256=sha(r['signed']),
                  inputs={str(p):sha(p) for p in (HERE/'trace.py', HERE/'host.c', command)})
    (out/'access.json').write_text(json.dumps(record, indent=2)+'\n')
    print(r['profile'], r['base'], 'TAGGED CRYPTO ACCESS TRACE PASS', flush=True)


if __name__ == '__main__':
    main()
