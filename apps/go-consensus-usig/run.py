#!/usr/bin/env python3
"""Rebuild and exercise the bounded serial USIG integration, including libraries."""
import argparse
import json
from pathlib import Path
import subprocess
from prepare import HERE, ROOT, sha

CONFIGS=(('BASELINE','BASELINE','0x40000000'),('RADIX_ONLY','RADIX_ONLY','0x40000000'),
         ('MAC27','MAC27','0x40000000'),('MAC27-high','MAC27','0x140000000'))
NORMAL='PASS mode=normal ecalls=81 ed25519=19 ecdsa=7 hmac=13 logs=2'


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,default=ROOT/'build/go-consensus-usig/all-compat-v1')
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
    record=dict(mode='SDK SIM and separate native tests',commands=[],configurations=[])
    def run(name,cmd,expected=0):
        cmd=list(map(str,cmd));r=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=600)
        log=out/(name+'.log');log.write_text(r.stdout+r.stderr)
        record['commands'].append(dict(name=name,command=cmd,returncode=r.returncode,log=str(log),sha256=sha(log)))
        (out/'matrix.json').write_text(json.dumps(record,indent=2)+'\n')
        assert r.returncode==expected,str(log)+'\n'+log.read_text()[-3000:]
        print(name,'PASS',flush=True)
    for name,profile,base in CONFIGS:
        b=out/name
        run(name+'-build',['python3',HERE/'build.py','--profile',profile,'--base',base,'--out',b])
        assert NORMAL in (b/'run.log').read_text()
        run(name+'-controls',['python3',HERE/'controls.py','--build',b])
        if profile!='BASELINE':run(name+'-trace',['python3',HERE/'trace.py','--build',b])
        record['configurations'].append(dict(name=name,profile=profile,base=base,build=str(b),result=NORMAL))
    run('native',['python3',HERE/'native.py','--out',out/'native'])
    run('vector-admission',['python3',HERE/'build.py','--profile','MAC27','--vector','--admission-only','--out',out/'vector-admission'],expected=1)
    vector=json.loads((out/'vector-admission/probe.json').read_text())
    assert not vector['admission_passed'],'review changed default-vector admission result'
    record['inputs']={str(p):sha(p) for p in [HERE/'run.py',HERE/'build.py',HERE/'finish.py',HERE/'controls.py',HERE/'trace.py',HERE/'native.py']}
    (out/'matrix.json').write_text(json.dumps(record,indent=2)+'\n')
    print('USIG MATRIX PASS: four SDK SIM configurations, 324 normal ECALLs, independent crypto oracles',flush=True)

if __name__=='__main__':main()
