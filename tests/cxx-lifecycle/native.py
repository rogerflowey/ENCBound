#!/usr/bin/env python3
"""Native real-runtime guard and registration-boundary controls."""
import hashlib,json,subprocess
import os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'build/integration/cxx-lifecycle/native';B.mkdir(parents=True,exist_ok=True)
SDK=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))
archive=SDK/'lib64/libsgx_tcxx.a'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='50731a201df955b9fab2f4b6292c5c9004bcfc089fa7af4ad956a97bb8fa1a21'
rows=[]
for profile in ('RADIX_ONLY','MAC27'):
 for opt in ('O0','O2'):
    exe=B/(profile+'-'+opt)
    flags=['-'+opt,'-g','-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime'),'-I'+str(ROOT/'tests')]
    if profile=='MAC27':flags+=['-DENCBOUND_MAC27']
    command=['clang-21',*flags,ROOT/'tests/cxx-lifecycle/native.c',ROOT/'tests/fake_platform.c',
        *[ROOT/f'runtime/{n}.c' for n in ('check_core','allocations','allocator','cxx_lifecycle')],
        archive,'-Wl,--wrap=__cxa_atexit','-o',exe]
    p=subprocess.run(list(map(str,command)),capture_output=True,text=True)
    (B/(exe.name+'-build.log')).write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr
    p=subprocess.run([exe],capture_output=True,text=True)
    (B/(exe.name+'.log')).write_text(p.stdout+p.stderr)
    assert p.returncode==0 and 'CXX LIFECYCLE NATIVE PASS' in p.stdout,(p.returncode,p.stdout,p.stderr)
    rows.append(dict(mode='native synthetic platform / real runtime and SDK guards',profile=profile,
        optimization=opt,result='pass',controls=9 if profile=='MAC27' else 6,
        exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),command=list(map(str,command))))
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX LIFECYCLE NATIVE PASS',len(rows),'rows, 30 attributed controls')
