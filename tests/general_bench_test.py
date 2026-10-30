#!/usr/bin/env python3
"""Regression tests for the benchmark's output/security oracles and admission."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent.parent
HERE=ROOT/'apps/general-bench'
sys.path.insert(0,str(HERE))
from diagnose import validate_security
from reference import NAMES
import prepare

def main(run,out):
    out.mkdir(parents=True,exist_ok=False)
    results=[]
    for profile in ['RADIX_ONLY','MAC27']:
        for mode in ['range','tag','raw']:
            text=(run/'diagnostics'/f'{profile}-{mode}.log').read_text()
            validate_security(text,profile,mode)
            mutations={'wrong entry':text.replace('ENTRY=1','ENTRY=0'),
                       'wrong size':text.replace('RADIX=17','RADIX=18'),
                       'wrong pointer':re.sub(r'INJECTED=0x[0-9a-f]+','INJECTED=0x1234',text)}
            if profile=='RADIX_ONLY' and mode=='tag':
                mutations['false output']=text.replace('"correct":true','"correct":false')
                mutations['failed exit']=text.replace('exited normally','exited with code 4')
            else:
                mutations['wrong signal']=text.replace('SIGILL','SIGSEGV')
                mutations['missing abort entry']=text.replace('ABORT entry=1','ABORT entry=0')
                mutations['wrong abort code']=re.sub(r'ABORT entry=1 code=\d+','ABORT entry=1 code=99',text)
                mutations['missing kernel frame']=re.sub(r'^#\d+ .*kernel_atax.*$', '#1 unrelated', text, flags=re.M)
                mutations['missing require entry']=text.replace('REQUIRE entry=1','REQUIRE entry=0')
                mutations['unrelated abort caller']=re.sub(r'^#1 .*encbound_require.*$', '#1 unrelated', text, flags=re.M)
                mutations['unrelated abort kernel']=re.sub(r'^#[23] .*kernel_atax.*$', '#2 unrelated', text, flags=re.M)
                mutations['returned before abort']=text+'\n{"correct":true}\n'
                mutations['wrong access']=text.replace('kind=1','kind=2')
                mutations['wrong checked bits']=re.sub(r'CHECK capability=0x[0-9a-f]+','CHECK capability=0x1234',text)
            for name,bad in mutations.items():
                try: validate_security(bad,profile,mode)
                except (RuntimeError,AttributeError): pass
                else: raise AssertionError((profile,mode,name))
            results.append({'test':profile+' '+mode+' oracle negatives','mutations':len(mutations),'status':'passed'})
    for profile in ['RADIX_ONLY','MAC27']:
        for mode in ['range','tag','raw']:
            path=run/'diagnostics'/f'{profile}-{mode}-prepared.log'
            if not path.exists(): continue
            text=path.read_text(); validate_security(text,profile,mode,True)
            for bad in [text.replace('PREPARED token=1','PREPARED token=0'),
                        text.replace('anchor=1','anchor=0')]:
                try: validate_security(bad,profile,mode,True)
                except RuntimeError: pass
                else: raise AssertionError('invalid prepared evidence accepted')
            results.append({'test':profile+' '+mode+' prepared oracle','status':'passed'})
    with tempfile.TemporaryDirectory(prefix='general-bench-tests-') as td:
        tmp=Path(td);adapt=tmp/'adapted';prepare.prepare(adapt)
        sources=[HERE/'driver.c',*sorted(adapt.glob('*.c'))]
        native=tmp/'sanitized'
        command=['clang-21','-O1','-g','-ffp-contract=off','-fsanitize=address,undefined',
                 '-fno-sanitize-recover=all','-DNATIVE','-I'+str(HERE),str(HERE/'host.c'),
                 *map(str,sources),'-o',str(native)]
        subprocess.run(command,check=True)
        (out/'sanitizer-command.json').write_text(json.dumps(command,indent=2)+'\n')
        for case,name in enumerate(NAMES):
            p=subprocess.run([str(native),str(case),str(run/'references'/(name+'.bin'))],
                             input='1\n3\n0\n',text=True,capture_output=True)
            (out/(name+'-sanitized.log')).write_text(p.stdout+p.stderr)
            assert p.returncode==0 and p.stdout.count('"correct":true')==2,(name,p.stderr)
            results.append({'test':name+' ASan/UBSan native correctness','status':'passed'})
        bad=tmp/'bad.bin';bad.write_bytes(b'\xff'*8)
        for profile in ['BASELINE','RADIX_ONLY','MAC27']:
            b=run/'artifacts'/profile
            env=dict(os.environ,LD_LIBRARY_PATH=str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[1] / 'deps/sgxsdk')) / 'lib64'))
            p=subprocess.run([str(b/'host'),'0',str(bad)],cwd=b,env=env,input='1\n0\n',text=True,capture_output=True)
            (out/(profile+'-bad-reference.log')).write_text(p.stdout+p.stderr)
            assert p.returncode==4 and 'incorrect result' in p.stderr and '"correct":true' not in p.stdout
            results.append({'test':profile+' corrupted output reference rejected','status':'passed'})
        main=tmp/'invalid.c';main.write_text('''#include "bench.h"
#include <assert.h>
int main(void) {
 unsigned char out[OUTPUT_BYTES];
 assert(bench_run(-1,1,out,8)==1);
 assert(bench_run(5,1,out,8)==1);
 assert(bench_run(0,0,out,8)==1);
 assert(bench_run(0,100001,out,8)==1);
 assert(bench_run(0,1,out,7)==1);
 assert(bench_run(0,1,0,8)==1);
 return 0;
}
''')
        subprocess.run(['clang-21','-O2','-ffp-contract=off','-I'+str(HERE),str(main),*map(str,sources),'-o',str(tmp/'invalid')],check=True)
        subprocess.run([str(tmp/'invalid')],check=True)
        results.append({'test':'invalid workload/count/size/null rejected','status':'passed'})
    for flag in ['PROFILE=unknown','SGX_MODE=HW','SGX_DEBUG=0','APP_FRONTEND_OPT=-O0','APP_CODEGEN_OPT=-O3','TRUSTED_OPT=-O3','TRUSTED_CORE=unknown','CHECK_REUSE=unknown','LOCAL_PROOFS=2']:
        p=subprocess.run(['make','-n','-C',str(HERE),flag],text=True,capture_output=True)
        assert p.returncode!=0,flag
        results.append({'test':'reject '+flag,'status':'passed'})
    (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print('GENERAL BENCH TESTS PASS',len(results),'groups')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True)
    p.add_argument('--out',type=Path);a=p.parse_args()
    main(a.run.resolve(),a.out.resolve() if a.out else a.run.resolve().parent/(a.run.name+'-tests'))
