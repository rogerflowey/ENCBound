#!/usr/bin/env python3
"""Build, audit and execute the matched bounded ConFlow SDK SIM matrix."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SDK = Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
sys.path.insert(0,str(HERE))
from native_controls import run as native_controls
from trace import trace


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out',type=Path,default=ROOT/'build/conflow/results.json')
    p.add_argument('--trace',action='store_true',help='Observe tagged stack and scratch writes with gdb')
    a = p.parse_args()
    rows = []
    for profile, base in [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),
                          ('MAC27','0x40000000'),('MAC27','0x140000000')]:
        suffix = '' if base=='0x40000000' else '-base'+base[2:]
        b = ROOT/'build/conflow'/('SIM-'+profile+'-feO2-cgO2-rtO2-fused'+suffix)
        b.mkdir(parents=True,exist_ok=True)
        command = ['make','-C',str(HERE),'-j4','PROFILE='+profile,'ENCLAVE_BASE='+base,
                   'SGX_SDK='+str(SDK)]
        with (b/'build.log').open('w') as log:
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
        env = dict(os.environ,ENCBOUND_TEST_BASE=base,
                   LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'))
        command = [b/'host/host',b/'enclave/enclave.signed.so']
        result = subprocess.run(command,env=env,capture_output=True,text=True,timeout=60)
        (b/'run.stdout').write_text(result.stdout)
        (b/'run.stderr').write_text(result.stderr)
        if result.returncode:
            raise SystemExit(str(b)+' failed:\n'+result.stderr)
        functional = json.loads(result.stdout)
        assert functional['result']=='PASS' and functional['calls']==384 and functional['comparisons']==2520
        inventory = json.loads((b/'inventory.json').read_text())
        access = trace(b) if a.trace and profile!='BASELINE' else None
        rows.append(dict(profile=profile,base=base,mode='SDK SIM',functional=functional,access_trace=access,
                         build=str(b),inventory=inventory,
                         retained_logs={n:sha(b/n) for n in ('build.log','run.stdout','run.stderr')},
                         prepared_sha256=sha(b/'prepared/prepared.json')))
        print(profile,base,'PASS',functional,flush=True)
    native = native_controls(Path(rows[0]['build']))
    sources = {str(f.relative_to(ROOT)):sha(f) for f in sorted(HERE.iterdir()) if f.is_file()}
    result = dict(application='conflow-dev/ConFlow selected operators',
                  observed_at=datetime.now(timezone.utc).isoformat(),
                  pins=json.loads((HERE/'pins.json').read_text()),
                  configuration='all-compat-v1; frontend O2; codegen O2; trusted O2 fused; SDK SIM debug; sequential',
                  sharing=dict(Ne=5,Nt=6,insert=4,indexs=[1,2,0,3,1,0]),
                  numerical_oracle='independent host double ReLU/sigmoid/stable softmax and vector-Jacobian products; abs 6e-6 + rel 3e-5',
                  rows=rows,native_controls=native,sources=sources,
                  claims=dict(functional=True,hardware=False,performance=False,protection=False,
                              full_tensorflow_workflow=False),
                  limits=['Original user_check arrays stay host memory; enclave scratch and mutable globals use protected slots.',
                          'Positive consistent bounded dimensions only; no hostile shape/length validation or resource exhaustion claim.',
                          'Finite fixtures only; NaN/Inf behavior and full numerical conformance are not established.',
                          'No redefinition of frozen experiment targets; no core compiler/runtime changes.'])
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2)+'\n')
    print('WROTE',a.out)


if __name__=='__main__':
    main()
