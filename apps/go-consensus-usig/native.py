#!/usr/bin/env python3
"""Native adapter contracts using the real runtime and recording SDK stand-ins."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
from prepare import HERE, ROOT, prepare, sha
from build import SDK
ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
out=a.out.resolve();out.mkdir(parents=True,exist_ok=True);record=dict(mode='native; synthetic platform and recording SDK stand-ins',commands=[],rows=[])
sources=[ROOT/'runtime'/f'{n}.c' for n in ('siphash','runtime','capability','allocations','allocator','adapters')]+[ROOT/'tests/fake_platform.c',HERE/'adapters.c',HERE/'adapters_test.c']
flags=['-O1','-g','-Wall','-Wextra',*['-I'+str(x) for x in (ROOT/'include',ROOT/'runtime',ROOT/'tests',HERE,SDK/'include')]]
def run(name,cmd):
 cmd=list(map(str,cmd));r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);log=out/(name+'.log');log.write_text(r.stdout+r.stderr)
 record['commands'].append(dict(command=cmd,returncode=r.returncode,log=str(log),sha256=sha(log)))
 (out/'native.json').write_text(json.dumps(record,indent=2)+'\n')
 assert not r.returncode,log.read_text()
 return r.stdout
for profile in ('RADIX_ONLY','MAC27'):
 objects=[]
 for i,src in enumerate(sources):
  obj=out/f'{profile}-{i}.o';run(obj.stem,['clang-21',*flags,*(['-DENCBOUND_MAC27'] if profile=='MAC27' else []),'-MMD','-MF',obj.with_suffix('.d'),'-c',src,'-o',obj]);objects.append(obj)
 binary=out/profile;run(profile+'-link',['clang-21',*objects,'-o',binary]);result=run(profile,[binary]);print(profile,result,flush=True)
 record['rows'].append(dict(profile=profile,output=result,binary=str(binary),sha256=sha(binary)))
helper=out/'crypto-helpers'
run('crypto-helpers-build',['clang-21',*flags,'-I'+str(prepare()/'trusted'),'-MMD','-MF',out/'crypto-helpers.d',HERE/'crypto_support.c',HERE/'crypto_support_test.c','-o',helper])
helper_output=run('crypto-helpers',[helper]);assert 'USIG CRYPTO HELPERS PASS:' in helper_output
record['helpers']=dict(output=helper_output,binary=str(helper),sha256=sha(helper))
deps={HERE/'native.py',HERE/'crypto_support.c',HERE/'crypto_support_test.c'}
for d in out.glob('*.d'):deps.update(Path(n).resolve() for n in shlex.split(d.read_text().replace('\\\n',' ').partition(':')[2]))
record['inputs']={str(n):sha(n) for n in sorted(deps)}
(out/'native.json').write_text(json.dumps(record,indent=2)+'\n')
