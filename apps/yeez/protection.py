#!/usr/bin/env python3
"""Attribute rejected SDK-service buffer accesses in the matched SIM fixture."""
import hashlib,json,os,subprocess
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1];B=R/'build/yeez/adapter-sim'
S=Path(os.environ.get('SGX_SDK',R/'deps/sgxsdk'))
rows=[]
for profile,base in [('RADIX_ONLY','0x40000000'),('MAC27','0x40000000'),('MAC27','0x140000000')]:
 out=B/(profile+'-'+base)
 for action,code,origin in [(100,4,'encbound_yeez_sha256'),(101,4,'encbound_yeez_encrypt'),
     (102,4,'encbound_yeez_dh_init'),(103,4,'encbound_yeez_dh_msg3'),(104,5,'encbound_yeez_dh_init')]:
  if profile=='RADIX_ONLY' and action==104:continue
  env=dict(os.environ,LD_LIBRARY_PATH=str(S/'sdk_libs')+':'+str(S/'lib64'),ENCBOUND_TEST_BASE=base)
  command=['gdb','-q','-batch','-ex','set pagination off','-ex','add-symbol-file '+str(out/'enclave.so')+' -o '+base,
      '-ex','run','-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt','--args',str(out/'host'),str(out/'enclave.signed.so'),str(action)]
  p=subprocess.run(command,env=env,text=True,capture_output=True,timeout=60);text=p.stdout+p.stderr
  log=B/f'protection-{profile}-{base}-{action}.log';log.write_text(text)
  assert p.returncode==0 and f'ABORT_CODE {code}\n' in text and 'encbound_abort' in text and 'encbound_require' in text and origin in text,text
  rows.append(dict(mode='SDK SIM / GDB',profile=profile,base=base,action=action,abort_code=code,origin=origin,
      image_sha256=hashlib.sha256((out/'enclave.signed.so').read_bytes()).hexdigest(),command=command,log=str(log),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))
  print(profile,base,action,'attributed',code,flush=True)
(B/'protection.json').write_text(json.dumps(rows,indent=2)+'\n')
print('YEEZ SDK SERVICE PROTECTION CONTROLS PASS',len(rows))
