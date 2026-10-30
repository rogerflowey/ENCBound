#!/usr/bin/env python3
"""Native SDK spies with real checks/allocator; no crypto or SGX result."""
import hashlib,json,os,subprocess
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1]
S=Path(os.environ.get('SGX_SDK',R/'deps/sgxsdk'))
B=R/'build/yeez/adapter-native';B.mkdir(parents=True,exist_ok=True)
rows=[]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
sources=[H/'adapters_test.c',R/'tests/fake_platform.c',*[R/f'runtime/{n}.c' for n in ('siphash','runtime','capability','allocations','allocator','adapters')]]
for profile in ('RADIX_ONLY','MAC27'):
 for opt in ('O0','O2'):
  key=profile+'-'+opt;exe=B/key
  command=['gcc','-g','-'+opt,'-Wall','-Wextra','-Wno-unused-parameter','-Werror','-DENCBOUND_PROTECTED',*(['-DENCBOUND_MAC27'] if profile=='MAC27' else []),*['-I'+str(p) for p in (R/'include',R/'runtime',R/'tests',S/'include')],*map(str,sources),'-o',str(exe)]
  p=subprocess.run(command,capture_output=True,text=True);(B/(key+'-build.log')).write_text(p.stdout+p.stderr)
  assert p.returncode==0,p.stderr
  p=subprocess.run([exe],capture_output=True,text=True,timeout=20);(B/(key+'-run.log')).write_text(p.stdout+p.stderr)
  assert p.returncode==0,(key,p.stdout,p.stderr)
  print(key,p.stdout.strip(),flush=True)
  rows.append(dict(profile=profile,opt=opt,command=command,output=p.stdout,image_sha256=sha(exe)))
(B/'results.json').write_text(json.dumps(dict(scope='native real runtime; SDK spies, no crypto/SGX result',rows=rows,inputs={str(p):sha(p) for p in [*sources,H/'adapters.c',H/'adapters.h',Path(__file__)]}),indent=2)+'\n')
