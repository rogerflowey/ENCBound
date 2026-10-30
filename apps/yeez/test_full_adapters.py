#!/usr/bin/env python3
import hashlib,json,subprocess,os
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1];S=Path(os.environ.get('SGX_SDK', R/'deps/sgxsdk'))
B=R/'build/yeez/full-adapter-native';B.mkdir(parents=True,exist_ok=True);rows=[]
for profile in ('RADIX_ONLY','MAC27'):
 for opt in ('O0','O2'):
  key=profile+'-'+opt;exe=B/key
  command=['gcc','-g','-'+opt,'-Wall','-Wextra','-Wno-unused-parameter','-Werror','-DENCBOUND_PROTECTED',
    *(['-DENCBOUND_MAC27'] if profile=='MAC27' else []),*['-I'+str(p) for p in (H,R/'include',R/'runtime',R/'tests',S/'include')],
    H/'full_adapters_test.c',R/'tests/fake_platform.c',*[R/f'runtime/{n}.c' for n in ('siphash','runtime','capability','allocations','allocator','adapters')],'-o',exe]
  q=subprocess.run(list(map(str,command)),capture_output=True,text=True);(B/(key+'-build.log')).write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr
  q=subprocess.run([exe],capture_output=True,text=True,timeout=20);(B/(key+'-run.log')).write_text(q.stdout+q.stderr);assert q.returncode==0,(key,q.stdout,q.stderr)
  print(key,q.stdout.strip(),flush=True);rows.append(dict(profile=profile,opt=opt,output=q.stdout,sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
