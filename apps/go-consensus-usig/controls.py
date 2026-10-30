#!/usr/bin/env python3
"""Attribute bounded error/resource controls through the original USIG ECALLs.

Do not classify libc++ assertions or allocator failures as spatial protection.
An additional watchpoint observes accepted out-of-object writes in SIM.
"""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import subprocess
from prepare import HERE, sha
from build import SDK

MODES=('key-overflow','ed-key-end','bad-counter','zero-counters','allocation-exhaustion')


def controls(build):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    build=build.resolve();r=json.loads((build/'build.json').read_text());p=r['profile']
    dest=build/'controls';dest.mkdir(exist_ok=True)
    env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'lib64'),ENCBOUND_TEST_BASE=r['base'])
    rows=[]
    def run(name,cmd):
        proc=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=60,env=env)
        log=dest/(name+'.log');log.write_text(proc.stdout+proc.stderr)
        return dict(command=list(map(str,cmd)),returncode=proc.returncode,log=str(log),sha256=sha(log)),log.read_text()
    for mode in MODES:
        accepted=p=='BASELINE' and mode in ('key-overflow','ed-key-end') or p=='RADIX_ONLY' and mode=='ed-key-end'
        direct,text=run(mode+'-direct',[r['host'],r['signed'],mode])
        assert direct['returncode']==(0 if accepted else -4),(mode,direct)
        if accepted:
            assert 'PASS mode='+mode+' ecalls=1 ' in text
            # Hardware access watchpoint catches even an unchanged zero byte.
            symbol='_ZL12usig_mac_key' if mode=='key-overflow' else '_ZL11edd25519_sk'
            nm=subprocess.check_output(['nm','-an',r['image']],text=True)
            address=int(re.search(r'^([0-9a-f]+) [a-zA-Z] '+symbol+'$',nm,re.M)[1],16)
            target=int(r['base'],16)+address+1024
            body=f'''awatch *(unsigned char*){target:#x}
continue
printf "USIG_OUTSIDE declared_size=1024 target=0x%lx\\n", (unsigned long){target:#x}
x/1bx {target:#x}
disassemble /r ecall_usig_init
bt 12
disable
continue
'''
            meaning='one-byte out-of-object write observed by an access watchpoint; call returns success'
        else:
            body='continue\nbt 16\n'
            if mode=='key-overflow':meaning='RANGE at checked strncpy destination extent (1025 bytes into 1024-byte global)'
            elif mode=='ed-key-end':meaning='TAG at original one-past NUL store (offset 1024 in 1024-byte global)'
            elif mode=='allocation-exhaustion':meaning='terminal new allocation failure; not spatial protection'
            else:meaning='existing libc++ vector subscript assertion; not ENCBound spatial protection'
        script=dest/(mode+'.gdb')
        script.write_text(f'''set pagination off
set confirm off
break usig_trace_ready
run
add-symbol-file {r['image']} -o {r['base']}
{body}''')
        debugger,text=run(mode+'-gdb',['gdb','-q','-batch','-x',script,'--args',r['host'],r['signed'],mode])
        assert debugger['returncode']==0,(mode,str(script))
        assert 'ecall_usig_init' in text or 'ecall_usig_create_ui_' in text
        if accepted:
            assert 'USIG_OUTSIDE declared_size=1024' in text and 'Hardware access (read/write) watchpoint' in text
            assert 'exited normally' in text and 'PASS mode='+mode in text
            if mode=='key-overflow':assert 'strncpy' in text
            else:assert re.search(r'movb\s+\$0x0,[^\n]+\n=>',text) and 'ecall_usig_init (' in text
        else:
            assert 'Program received signal SIGILL' in text
            if mode=='key-overflow':
                assert 'encbound_abort (code=4)' in text and 'encbound_strncpy' in text and 'n=1025' in text and 'usig_enclave.cpp:129' in text
            elif mode=='ed-key-end':assert 'encbound_abort (code=5)' in text and 'usig_enclave.cpp:134' in text
            elif mode=='allocation-exhaustion':
                assert 'encbound_cxx_new' in text and 'allocate (' in text
                if p!='BASELINE':assert 'code=code@entry=7' in text
            else:assert 'encbound_cxx_assert' in text and '__n < size()' in text and 'encbound_abort' not in text
        rows.append(dict(case=mode,meaning=meaning,direct=direct,debugger=debugger,
            script=str(script),script_sha256=sha(script)))
        print(p,r['base'],mode,meaning,flush=True)
    record=dict(mode='SDK SIM',profile=p,base=r['base'],signed=r['signed'],signed_sha256=sha(r['signed']),
        rows=rows,inputs={str(n):sha(n) for n in (HERE/'controls.py',HERE/'host.c')})
    (build/'controls.json').write_text(json.dumps(record,indent=2)+'\n')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--build',type=Path,required=True);controls(ap.parse_args().build)
