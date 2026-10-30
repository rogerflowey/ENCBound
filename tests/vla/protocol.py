#!/usr/bin/env python3
import hashlib,json,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];H=Path(__file__).resolve().parent
B=R/'build/integration/vla/protocol';B.mkdir(parents=True,exist_ok=True)
rows=[]
for opt in ('O0','O2'):
 for profile in ('RADIX_ONLY','MAC27'):
    key=profile+'-'+opt;exe=B/key
    flags=['-DENCBOUND_MAC27'] if profile=='MAC27' else []
    command=['clang-21','-'+opt,'-g',*flags,*['-I'+str(R/d) for d in ('include','runtime','tests')],
        H/'protocol.c',R/'tests/fake_platform.c',
        *[R/f'runtime/{n}.c' for n in ('check_core','allocator','allocations')],'-o',exe]
    for name,cmd in [('build',command),('run',[exe])]:
        p=subprocess.run(list(map(str,cmd)),text=True,capture_output=True)
        (B/(key+'-'+name+'.log')).write_text(p.stdout+p.stderr)
        assert p.returncode==0,(p.returncode,p.stdout,p.stderr)
    rows.append(dict(profile=profile,optimization=opt,result='pass',controls=12,
        command=list(map(str,command)),exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('VLA PROTOCOL PASS: four rows, 48 attributed controls')
