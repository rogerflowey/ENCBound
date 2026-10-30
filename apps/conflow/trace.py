#!/usr/bin/env python3
"""Observe real tagged stack/random and heap/scratch accesses in SDK SIM.

Uses apps/fedserving/trace.py's existing debugger technique. Successful checks
are execution evidence, not a vulnerability-prevention result.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
SDK = Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))


def trace(build):
    b = build.resolve()
    config = json.loads((b/'build-config.json').read_text())
    assert config['profile'] in ('RADIX_ONLY','MAC27')
    base = int(config['base'],16)
    image = b/'enclave/enclave.signed.so'
    sections = subprocess.check_output(['readelf','-SW',image],text=True)
    text_rva = int(re.search(r'\]\s+\.text\s+PROGBITS\s+(\S+)',sections)[1],16)
    symbols = subprocess.check_output(['nm','-n',image],text=True)
    softmax = int(re.search(r'^(\S+) [tT] ecall_softmax$',symbols,re.M)[1],16)+base
    line = next(i for i,s in enumerate((HERE/'host.c').read_text().splitlines(),1)
                if s.strip().startswith('four_app_permissions('))
    commands = b/'access.gdb'
    commands.write_text(f'''set pagination off
set confirm off
break {HERE/'host.c'}:{line}
run
add-symbol-file {image} {base+text_rva:#x}
tbreak encbound_conflow_rand
continue
tbreak encbound_require
continue
printf "CONFLOW_STACK capability=0x%lx width=%lu kind=%d\\n", $rdi, $rsi, $rdx
bt 6
finish
printf "CONFLOW_STACK_RAW address=0x%lx\\n", $rax
tbreak *{softmax:#x}
continue
tbreak encbound_require
continue
printf "CONFLOW_HEAP capability=0x%lx width=%lu kind=%d\\n", $rdi, $rsi, $rdx
bt 6
finish
printf "CONFLOW_HEAP_RAW address=0x%lx\\n", $rax
disable
continue
''')
    cmd = ['gdb','-q','-batch','-x',str(commands),'--args',str(b/'host/host'),str(image)]
    result = subprocess.run(cmd,capture_output=True,text=True,timeout=60,
                            env=dict(os.environ,ENCBOUND_TEST_BASE=config['base'],
                                     LD_LIBRARY_PATH=str(SDK/'lib64')+':'+str(SDK/'sdk_libs')))
    log = b/'access.log'
    text = result.stdout+result.stderr
    log.write_text(text)
    assert result.returncode==0 and 'exited normally' in text and 'received signal' not in text, str(log)
    accesses = []
    for domain, width in [('STACK',10),('HEAP',48)]:
        match = re.search(r'^CONFLOW_'+domain+r' capability=(0x[0-9a-f]+) width=(\d+) kind=(\d+)$',text,re.M)
        raw = re.search(r'^CONFLOW_'+domain+r'_RAW address=(0x[0-9a-f]+)$',text,re.M)
        assert match and raw, str(log)
        capability, actual_width, kind = map(lambda x:int(x,0),match.groups())
        address = int(raw[1],16)
        assert 1<=capability>>59<=30 and address==base+(capability&0xffffffff)
        assert actual_width==width and kind==2
        accesses.append(dict(domain=domain,capability=hex(capability),raw=hex(address),width=width,kind=kind))
    assert 'encbound_conflow_rand' in text and 'ecall_softmax' in text and '"result":"PASS"' in text
    record = dict(profile=config['profile'],base=config['base'],mode='SDK SIM',accesses=accesses,
                  command=cmd,log=str(log),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                  signed_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                  claim='successful tagged stack and heap checks; no attack or hardware claim')
    (b/'access.json').write_text(json.dumps(record,indent=2)+'\n')
    return record


if __name__=='__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build',type=Path,required=True)
    print(json.dumps(trace(p.parse_args().build),indent=2))
