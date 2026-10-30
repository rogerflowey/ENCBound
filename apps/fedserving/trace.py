#!/usr/bin/env python3
"""Attribute an exercised source access to its runtime check in SDK SIM.

The original user_check model array is canonical host memory. This trace does
not assert tagged model storage or vulnerability prevention.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from run import ROOT, HERE, SDK, verify


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=ROOT/'build/first10-2026-10-21/fedserving')
    a = p.parse_args()
    out = a.out.resolve()
    rows = []
    for name, base in [('RADIX_ONLY',0x40000000),('MAC27',0x40000000),('MAC27-high',0x140000000)]:
        build = out/name
        image = build/'enclave/enclave.so'
        sections = subprocess.check_output(['readelf','-SW',image],text=True)
        rva = int(re.search(r'\]\s+\.text\s+PROGBITS\s+(\S+)',sections)[1],16)
        command = out/(name+'-access.gdb')
        command.write_text(f'''set pagination off
set confirm off
break {HERE/'host.c'}:20
run {build/'enclave/enclave.signed.so'}
add-symbol-file {image} {base+rva:#x}
tbreak _Z10cal_outputP10ModelInputPA10_d
continue
tbreak encbound_require
continue
printf "FEDSERVING_ACCESS capability=0x%lx width=%lu kind=%d\\n", capability, width, kind
bt 10
finish
printf "FEDSERVING_RAW address=0x%lx\\n", $rax
disable
continue
''')
        cmd = ['gdb','-q','-batch','-x',str(command),'--args',str(build/'host/host')]
        env = dict(os.environ,LD_LIBRARY_PATH=f'{SDK}/sdk_libs:{SDK}/lib64',ENCBOUND_TEST_BASE=hex(base))
        proc = subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=120)
        text = proc.stdout+proc.stderr
        log = out/(name+'-access.log'); log.write_text(text)
        access = re.search(r'^FEDSERVING_ACCESS capability=(0x[0-9a-f]+) width=(\d+) kind=(\d+)$',text,re.M)
        raw = re.search(r'^FEDSERVING_RAW address=(0x[0-9a-f]+)$',text,re.M)
        if proc.returncode or not access or not raw or 'exited normally' not in text or 'received signal' in text:
            raise ValueError('incomplete check trace: '+str(log))
        cap,width,kind = map(lambda s:int(s,0),access.groups())
        address = int(raw[1],16)
        if (cap != address or cap >> 59 or width != 16 or kind != 1 or
                base <= cap < base+0x40000000 or 'cal_output (' not in text or 'turth_discovery (' not in text):
            raise ValueError('wrong source check/host-memory geometry: '+str(log))
        verify([json.loads(line) for line in proc.stdout.splitlines() if line.startswith('{"case":')])
        rows.append(dict(configuration=name,mode='SDK SIM',command=cmd,capability=hex(cap),
                         raw=hex(address),width=width,kind=kind,domain='canonical host user_check input',
                         log=str(log),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                         signed_sha256=hashlib.sha256((build/'enclave/enclave.signed.so').read_bytes()).hexdigest()))
        print(name,'SOURCE ACCESS TRACE PASS',flush=True)
    (out/'access-traces.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__ == '__main__':
    main()
