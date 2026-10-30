#!/usr/bin/env python3
"""Matched SDK SIM combiner matrix and independent full numerical oracle."""
import argparse
import copy
import hashlib
import json
import math
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))

def reference(test):
    # Reimplement the published L2 equations, including the upstream denominator
    # and output/update order. No application binary is used as an oracle.
    preds = [[[0.0 if test == 0 else (k+1)/55.0 if test == 1 else
               (1+((i+1)*(k+3)+(j+2)*(test+1))%31)/100.0
               for k in range(10)] for j in range(16)] for i in range(6)]
    weights = [1.0]*6
    for _ in range(20):
        denominator = sum([weights[0]]*6)
        output = [[sum(weights[i]*preds[i][j][k] for i in range(6))/denominator
                   for k in range(10)] for j in range(16)]
        losses = [sum(math.sqrt(sum(math.pow(preds[i][j][k]-output[j][k],2)
                                   for k in range(10))) for j in range(16)) for i in range(6)]
        total = sum(losses)
        next_weights = [weights[i] if total == 0 or losses[i] == 0 else
                        -math.log(losses[i]/total) for i in range(6)]
        denominator = sum(math.exp(w) for w in next_weights)
        weights = [math.exp(w)/denominator for w in next_weights]
    return dict(case=test, weights=weights, preds=[x for row in output for x in row])

def verify(rows):
    if len(rows) != 6:
        raise ValueError('expected six complete responses')
    for i, row in enumerate(rows):
        expected = reference(i)
        if row.get('case') != i:
            raise ValueError('wrong case order')
        for field in ('weights','preds'):
            if len(row.get(field,[])) != len(expected[field]):
                raise ValueError('incomplete '+field)
            if not all(isinstance(x,(int,float)) and math.isfinite(x) and
                       math.isclose(x,y,rel_tol=1e-9,abs_tol=1e-11)
                       for x,y in zip(row[field],expected[field])):
                raise ValueError('numerical mismatch: case '+str(i)+' '+field)

def oracle_controls():
    good = [reference(i) for i in range(6)]
    verify(good)
    bad = []
    changed = copy.deepcopy(good); changed[3]['preds'][119] += 0.01; bad.append(changed)
    changed = copy.deepcopy(good); changed[1]['weights'][5] = float('nan'); bad.append(changed)
    changed = copy.deepcopy(good); changed[0]['preds'].pop(); bad.append(changed)
    bad.append(good[:-1])
    bad.append(good[::-1])
    for rows in bad:
        try: verify(rows)
        except ValueError: pass
        else: raise AssertionError('oracle accepted a damaged response')
    return len(bad)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,default=ROOT/'build/first10-2026-10-21/fedserving')
    p.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'])
    p.add_argument('--plugin',type=Path,help='Use a retained compiler plugin for a fixed campaign')
    a = p.parse_args()
    out = a.out.resolve(); out.mkdir(parents=True,exist_ok=True)
    controls = oracle_controls()
    matrix = [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),
              ('MAC27','0x40000000'),('MAC27','0x140000000')]
    if a.profile: matrix = [(p,b) for p,b in matrix if p == a.profile]
    results = []
    for profile, base in matrix:
        name = profile+('-high' if base != '0x40000000' else '')
        build = out/name
        cmd = ['make','-C',HERE,'PROFILE='+profile,'ENCLAVE_BASE='+base,'BUILD='+str(build),'-j2']
        if a.plugin:
            cmd.append('PLUGIN='+str(a.plugin.resolve()))
        with (out/(name+'-build.log')).open('w') as log:
            subprocess.run(list(map(str,cmd)),stdout=log,stderr=subprocess.STDOUT,check=True)
        env = dict(os.environ,LD_LIBRARY_PATH=f'{SDK}/sdk_libs:{SDK}/lib64',ENCBOUND_TEST_BASE=base)
        command = [build/'host/host',build/'enclave/enclave.signed.so']
        proc = subprocess.run(command,capture_output=True,text=True,env=env,timeout=120)
        (out/(name+'-stdout.log')).write_text(proc.stdout)
        (out/(name+'-stderr.log')).write_text(proc.stderr)
        if proc.returncode:
            raise RuntimeError(name+' failed: '+str(proc.returncode)+' '+proc.stderr[-1200:])
        rows = [json.loads(s) for s in proc.stdout.splitlines()]
        verify(rows)
        if 'loaded app page permissions: PASS' not in proc.stderr:
            raise ValueError('missing loaded permission evidence')
        inventory = json.loads((build/'inventory.json').read_text())
        results.append(dict(configuration=name,profile=profile,base=base,mode='SDK SIM',
                            calls=len(rows),results=rows,build=str(build),build_command=list(map(str,cmd)),
                            host_command=list(map(str,command)),inventory=inventory,
                            stdout_sha256=hashlib.sha256(proc.stdout.encode()).hexdigest(),
                            stderr_sha256=hashlib.sha256(proc.stderr.encode()).hexdigest()))
        print(name,'PASS',len(rows),'complete numerical responses',flush=True)
    (out/'results.json').write_text(json.dumps(dict(rows=results,oracle_negative_controls=controls,
         dimensions=dict(queries=16,models=6,categories=10,iterations=20),
         limits='Bounded original L2 combiner on saved synthetic predictions; user_check inputs/outputs remain host memory. No ML training, KL, 7000-query capacity, vulnerability-prevention, hardware or performance claim.'),indent=2)+'\n')

if __name__ == '__main__':
    main()
