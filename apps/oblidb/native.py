#!/usr/bin/env python3
"""Finite native adapter tests, explicitly separate from SDK execution."""
import os
import argparse
import json
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SDK=Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))

def run(out):
    out.mkdir(parents=True,exist_ok=True)
    rows=[]
    sources=[ROOT/'runtime'/f'{n}.c' for n in ('siphash','runtime','capability','allocations','allocator','adapters')]
    sources += [ROOT/'tests/fake_platform.c',HERE/'crypto.c',HERE/'crypto_test.c']
    for profile in ('RADIX_ONLY','MAC27'):
        for opt in ('-O0','-O2'):
            binary=out/(profile+opt)
            command=['clang-21',opt,'-g','-DENCBOUND_PROTECTED',
                     *['-I'+str(ROOT/n) for n in ('include','runtime','tests')],'-I'+str(SDK/'include')]
            if profile=='MAC27':command+=['-DENCBOUND_MAC27']
            command += [*map(str,sources),'-o',str(binary)]
            subprocess.run(command,check=True)
            result=subprocess.run([binary],capture_output=True,text=True,check=True)
            (out/(binary.name+'.log')).write_text(result.stdout+result.stderr)
            rows.append(dict(mode='native fake platform; recording SDK stand-ins',profile=profile,
                             optimization=opt,command=command,result=result.stdout.strip()))
    (out/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
    return rows

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    print(json.dumps(run(p.parse_args().out.resolve()),indent=2))
