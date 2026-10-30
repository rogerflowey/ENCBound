#!/usr/bin/env python3
"""Attribute SDK SIM payload checks and terminal boundaries with GDB."""
import hashlib,json,os,resource,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];B=R/'build/integration/cxx-eh-rtti'
S=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))
resource.setrlimit(resource.RLIMIT_CORE,(0,0));rows=[]
for profile,base in [('RADIX_ONLY','0x40000000'),('MAC27','0x40000000'),('MAC27','0x140000000')]:
 out=B/f'{profile}-{base}-O2-O2'
 for case,code,origin in [(100,4,'exercise'),(101,5,'exercise'),(102,3,'exercise'),(103,1,'no_throw'),(104,None,'__encbound_eh_entry_exercise'),(105,4,'BadCleanup::~BadCleanup'),(120,4,'__encbound_app_dynamic_cast'),(121,5,'__encbound_app_dynamic_cast')]:
  if profile=='RADIX_ONLY' and case in (101,121):continue
  env=dict(os.environ,LD_LIBRARY_PATH=str(S/'sdk_libs')+':'+str(S/'lib64'),ENCBOUND_TEST_BASE=base)
  command=['gdb','-q','-batch','-ex','set pagination off','-ex','add-symbol-file '+str(out/'enclave.so')+' -o '+base,
           '-ex','run','-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt','--args',str(out/'host'),str(out/'enclave.signed.so'),str(case)]
  p=subprocess.run(command,env=env,text=True,capture_output=True,timeout=60)
  text=p.stdout+p.stderr;log=B/f'protection-{profile}-{base}-{case}.log';log.write_text(text)
  assert p.returncode==0 and origin in text,(case,text)
  if code is not None: assert f'ABORT_CODE {code}\n' in text and 'encbound_abort' in text,(case,text)
  else: assert ' in abort ()' in text and 'encbound_cxx_fail' in text,(case,text)
  if case in (100,101,102,105,120,121):assert 'encbound_require' in text,text
  rows.append(dict(mode='SDK SIM / GDB attribution',profile=profile,base=base,case=case,abort_code=code,origin=origin,
                   result='pass',image_sha256=hashlib.sha256((out/'enclave.signed.so').read_bytes()).hexdigest(),log=str(log)))
  print(profile,base,case,'attributed',code,flush=True)
(B/'protection.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX EH SDK SIM PROTECTION PASS',len(rows))
