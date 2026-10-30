#!/usr/bin/env python3
"""Actual alternate machine stack and checked runtime; no SGX claim."""
import hashlib,json,os,resource,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];H=Path(__file__).resolve().parent
B=R/'build/integration/vla/native';B.mkdir(parents=True,exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
commands=[];rows=[]
def run(name,cmd,env=None,good=True):
    p=subprocess.run(list(map(str,cmd)),env=env,text=True,capture_output=True,timeout=120)
    (B/(name+'.log')).write_text(p.stdout+p.stderr)
    commands.append(dict(command=list(map(str,cmd)),returncode=p.returncode,log=name+'.log'))
    assert (p.returncode==0)==good,(name,p.returncode,p.stdout,p.stderr)
    return p
run('plugin',['make','-C',R/'pass'])
admit=B/'admitted.txt';admit.write_text('vla_observe\nvla_edge\nvla_destroyed\n')
for fe in ('O0','O2'):
 for cg in ('O0','O2'):
  for profile in ('BASELINE','RADIX_ONLY','MAC27'):
    key=f'{profile}-{fe}-{cg}';obj=B/(key+'.o')
    env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_CODEGEN_OPT='-'+cg,ENCBOUND_VLA='1',ENCBOUND_ADMITTED=str(admit))
    run(key+'-app',[R/'tools/encbound-cc.sh',H/'app.c',obj,'-'+fe,'-g','-Xclang','-disable-O0-optnone'],env)
    cpp=B/(key+'-cpp.o')
    run(key+'-cpp',[R/'tools/encbound-cc.sh',H/'app.cpp',cpp,'-x','c++','-std=c++17','-fno-exceptions',
        '-fno-rtti','-'+fe,'-g','-Xclang','-disable-O0-optnone'],env)
    flags=['-DPROTECTED'] if profile!='BASELINE' else []
    if profile=='MAC27':flags+=['-DENCBOUND_MAC27']
    exe=B/key
    run(key+'-link',['clang-21','-g','-O2',*flags,*['-I'+str(R/d) for d in ('include','runtime','tests')],
        H/'native.c',H/'observer.c',R/'tests/fake_platform.c',
        *[R/f'runtime/{n}.c' for n in ('check_core','allocator','allocations','adapters')],obj,cpp,'-o',exe])
    p=run(key+'-run',[exe]);assert 'VLA NATIVE PASS' in p.stdout
    ir=obj.with_suffix('.checked.ll').read_text()
    if profile!='BASELINE':
        assert '@encbound_stack_prepare' in ir and '@encbound_stack_mint_dynamic' in ir
        # No application stores of raw stack state survive O0 promotion.
        assert not any('store ptr %' in l and 'encbound.vla.sp' in l for l in ir.splitlines())
    rows.append(dict(profile=profile,frontend=fe,codegen=cg,result='pass',output=p.stdout.strip(),
                     exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
    print(key,p.stdout.strip(),flush=True)
(B/'results.json').write_text(json.dumps(dict(scope='native fake platform / actual alternate stack / real runtime',rows=rows,commands=commands),indent=2)+'\n')
