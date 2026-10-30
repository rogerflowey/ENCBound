#!/usr/bin/env python3
"""Real compiler/runtime global slots, relocation semantics and rejection gates.

Native execution is an auxiliary mechanism test, never an SGX hardware result.
SDK integration commands and evidence live in the protected-globals record.
"""
from pathlib import Path
import hashlib
import json
import os
import resource
import subprocess
import sys

R=Path(__file__).resolve().parents[2]
B=R/'build/integration/protected-globals'
B.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(R/'tools'))
from audit_app_globals import audit
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
rows=[]
def run(cmd, *, env=None, good=True, name='command'):
    p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env)
    (B/(name+'.log')).write_text(p.stdout+p.stderr)
    assert (p.returncode==0)==good,(name,p.returncode,p.stderr)
    return p

run(['make','-C',R/'pass'],name='plugin')
for profile in ('BASELINE','RADIX_ONLY','MAC27'):
    out=B/profile;out.mkdir(exist_ok=True)
    flags=['-O1','-g','-fpie','-I'+str(R/'include'),'-I'+str(R/'runtime')]
    if profile=='MAC27':flags+=['-DENCBOUND_MAC27']
    runtime=[]
    for n in ('runtime','siphash','capability','allocations','allocator'):
        obj=out/(n+'.o')
        run(['clang-21',*flags,'-c',R/f'runtime/{n}.c','-o',obj],name=profile+'-'+n)
        runtime.append(obj)
    for opt,base,reuse,proofs,fast in [('O1','0x40000000','off','0','off'),
                                       ('O2','0x140000000','loop','1','inline')]:
        key=profile+'-'+opt
        env=dict(os.environ,ENCBOUND_PROTECTED_GLOBALS='1',ENCBOUND_PROFILE=profile,
                 ENCBOUND_CODEGEN_OPT='-'+opt if opt=='O2' else '-O0',
                 ENCBOUND_CHECK_REUSE=reuse,ENCBOUND_LOCAL_PROOFS=proofs,ENCBOUND_FAST_PATHS=fast)
        objects=[]
        for n in ('app','other'):
            obj=out/(n+'-'+opt+'.o')
            run([R/'tools/encbound-cc.sh',R/f'tests/integration/protected_globals_{n}.c',obj,
                 '-'+opt,'-fno-common','-fno-builtin','-fpie'],env=env,name=key+'-'+n)
            placed=out/(n+'-'+opt+'.app.o')
            run(['python3',R/'tools/mark_app_globals.py',obj,placed],name=key+'-'+n+'-place')
            objects.append(placed)
        exe=out/('test-'+opt)
        linkmap=out/('test-'+opt+'.map')
        harness=out/'native.o'
        run(['clang-21',*flags,'-c',R/'tests/integration/protected_globals_native.c','-o',harness],name=key+'-harness')
        extra=[]
        if profile=='MAC27' and opt=='O1':
            auxiliary=B/'auxiliary.c';auxiliary.write_text('int auxiliary(void){return 0;}')
            raw=B/'auxiliary.raw.o'
            extra=[B/'auxiliary.app.o']
            run(['clang-21','-c',auxiliary,'-o',raw],name='auxiliary-compile')
            run(['python3',R/'tools/mark_app_globals.py',raw,extra[0]],name='auxiliary-place')
        run(['clang-21',*flags,harness,*objects,*runtime,*extra,
             '-pie','-Wl,-Map,'+str(linkmap),'-Wl,-Ttext-segment='+base,
             '-Wl,-T,'+str(R/'sdk/enclave_sections.lds'),'-o',exe],name=key+'-link')
        linked=[Path(line[5:]) for line in linkmap.read_text().splitlines()
                if line.startswith('LOAD ') and line.endswith('.o')]
        trusted=[p for p in linked if p.resolve() not in {o.resolve() for o in objects}]
        audit(exe,objects,trusted,linkmap)
        rows.append(dict(kind='audit',profile=profile,frontend=opt,case='ELF-slot-geometry-and-permissions',result='pass'))
        if extra:
            # A code-only unit cannot bypass the all-unit mode check merely
            # because it has no writable definitions or cell references.
            try:audit(exe,objects+extra,[p for p in trusted if p not in extra],linkmap)
            except ValueError as e:assert str(e)=='mixed application global protection modes',str(e)
            else:raise AssertionError('mixed code-only global mode admitted')
            rows.append(dict(kind='audit',case='mixed-code-only-mode',result='pass'))
        expected={'session':'SESSION PASS'}
        if profile!='BASELINE':
            expected.update(raw='STOP 3',table='STOP 3',padding='PADDING PASS',crossing='STOP 4',
                            rebase='STOP 5' if profile=='MAC27' else 'REBASE ADMITTED',free='STOP 3')
            expected['invalid-entry']='STOP 3';expected['bad-slot']='INIT FAILURE TERMINAL'
        for case,want in expected.items():
            p=run([exe,case],name=key+'-'+case)
            assert p.stdout.strip()==want,(key,case,p.stdout,want)
            rows.append(dict(kind='native',profile=profile,frontend=opt,base=base,case=case,result='pass',observed=want))

rejects={
 'readonly-pointer':'int g; int *const p=&g;',
 'readonly-record':'int g; struct r {int *p;}; const struct r x={&g};',
 'weak':'__attribute__((weak)) int g;',
 'custom-section':'int g __attribute__((section(".other")));',
 'forged-cell':'unsigned long __encbound_gcap_g;',
 'forged-namespace':'int __encbound_fake;',
 'forged-section':'int g __attribute__((section("encbound_gcaps")));',
 'tls':'_Thread_local int g;',
 'helper-call':'unsigned long encbound_global_cap(const void*); unsigned long f(void*p){return encbound_global_cap(p);}',
}
for name,source in rejects.items():
    src=B/(name+'.c');src.write_text(source)
    p=run([R/'tools/encbound-cc.sh',src,B/(name+'.o'),'-O0','-fno-common'],
          env=dict(os.environ,ENCBOUND_PROFILE='MAC27',ENCBOUND_PROTECTED_GLOBALS='1'),good=False,name=name)
    assert 'ENCBound:' in p.stderr,(name,p.stderr)
    rows.append(dict(kind='admission',case=name,result='pass'))

# A declaration compiled for the new ABI cannot silently link against an old
# raw definition: its capability-cell symbol is absent.
plain=B/'plain-other.o'
run(['clang-21','-O1','-fpie','-c',R/'tests/integration/protected_globals_other.c','-o',plain],name='mixed-compile')
p=run(['clang-21',B/'MAC27/app-O1.o',plain,'-nostdlib','-Wl,--no-undefined','-o',B/'mixed'],good=False,name='mixed-link')
assert '__encbound_gcap_external_' in p.stderr
rows.append(dict(kind='link',case='mixed-raw-definition',result='pass'))

# Independent output verifier rejects an arbitrary table address.
src=B/'bad-accessor.ll'
src.write_text('target triple = "x86_64-pc-linux-gnu"\n'
               'declare i64 @encbound_global_cap(ptr)\n'
               'define i64 @f(ptr %p) { %x=call i64 @encbound_global_cap(ptr %p)\nret i64 %x\n}\n')
p=run(['opt-21','-load-pass-plugin='+str(R/'build/pass/encbound_pass.so'),'-passes=encbound-verify',
       '-disable-output',src],good=False,name='bad-accessor')
assert 'invalid global capability accessor' in p.stderr
rows.append(dict(kind='verifier',case='arbitrary-table-address',result='pass'))
record=dict(rows=rows,mode='native/compiler',limitations='No SGX hardware or timing result.',
            sources={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                     [R/'pass/encbound_globals.h',R/'runtime/runtime.c',R/'runtime/capability.c',Path(__file__)]})
(B/'results.json').write_text(json.dumps(record,indent=2)+'\n')
print('PROTECTED GLOBALS PASS',len(rows),'native/compiler rows')
