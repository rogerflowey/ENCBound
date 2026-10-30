#!/usr/bin/env python3
"""Attribute a successful original Ed25519 access in the protected SIM image.

Uses the existing sk-sgx trace pattern; no image or application modification.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from prepare import HERE, sha
from build import SDK


def trace(build):
    build=build.resolve();r=json.loads((build/'build.json').read_text())
    assert r['profile']!='BASELINE'
    image=Path(r['image']);base=int(r['base'],16)
    sections=subprocess.check_output(['readelf','-SW',image],text=True)
    rva=int(re.search(r'\]\s+\.text\s+PROGBITS\s+(\S+)',sections)[1],16)
    script=build/'access.gdb'
    script.write_text(f'''set pagination off
set confirm off
break usig_trace_ready
run
add-symbol-file {image} {base+rva:#x}
tbreak crypto_sign_ed25519_ref_fe25519_add
continue
tbreak encbound_require
continue
printf "USIG_ACCESS capability=0x%lx width=%lu kind=%d\\n", capability, width, kind
bt 10
finish
printf "USIG_RAW address=0x%lx\\n", $rax
disable
continue
''')
    cmd=['gdb','-q','-batch','-x',str(script),'--args',r['host'],r['signed']]
    proc=subprocess.run(cmd,capture_output=True,text=True,timeout=120,
        env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'lib64'),ENCBOUND_TEST_BASE=r['base']))
    text=proc.stdout+proc.stderr;log=build/'access.log';log.write_text(text)
    match=re.search(r'^USIG_ACCESS capability=(0x[0-9a-f]+) width=(\d+) kind=(\d+)$',text,re.M)
    raw=re.search(r'^USIG_RAW address=(0x[0-9a-f]+)$',text,re.M)
    assert not proc.returncode and match and raw and 'exited normally' in text,str(log)
    assert 'received signal' not in text and 'crypto_sign_ed25519_ref_fe25519_add (' in text
    cap,width,kind=[int(x,0) for x in match.groups()];address=int(raw[1],16)
    assert 1<=cap>>59<=30 and address==base+(cap&0xffffffff) and width==4 and kind==1
    assert 'PASS mode=normal ecalls=81 ed25519=19 ecdsa=7 hmac=13 logs=2' in text
    row=dict(profile=r['profile'],base=r['base'],mode='SDK SIM',command=cmd,
        capability=hex(cap),raw=hex(address),width=width,kind=kind,
        meaning='successful compiler-inserted tagged access in upstream fe25519_add; not a protection attack',
        log=str(log),log_sha256=sha(log),signed_sha256=sha(r['signed']),
        inputs={str(p):sha(p) for p in (HERE/'trace.py',HERE/'host.c',script)})
    (build/'access.json').write_text(json.dumps(row,indent=2)+'\n')
    print(r['profile'],r['base'],'TAGGED CRYPTO ACCESS PASS',flush=True)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--build',type=Path,required=True);trace(ap.parse_args().build)
