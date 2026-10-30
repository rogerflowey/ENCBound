#!/usr/bin/env python3
"""Debugger fault injection into ordinary checked application read arguments.

Private addresses are read by GDB only; no application ABI exposes them. The
SDK header/context is live when injected. TLS comes from the pinned SIM thread
lookup sequence, and the trace must reject before the application load.
"""
import hashlib,json,os,resource,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];B=R/'build/integration/cxx-eh-rtti'
S=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))
resource.setrlimit(resource.RLIMIT_CORE,(0,0));rows=[]
for profile,base in [('RADIX_ONLY','0x40000000'),('MAC27','0x40000000'),('MAC27','0x140000000')]:
 out=B/f'{profile}-{base}-O2-O2';image=out/'enclave.so'
 syms={line.split()[-1]:int(line.split()[0],16) for line in subprocess.check_output(['nm','--defined-only',str(image)],text=True).splitlines() if len(line.split())==3}
 live=int(base,16)+syms['_ZN12_GLOBAL__N_14liveE']
 for case in ('header','unwind-header','sdk-tls','unwind-context'):
  ex=['set pagination off','set breakpoint pending on','add-symbol-file '+str(image)+' -o '+base,
      'break sgx_ecall','run','disable 1']
  if case=='unwind-context':
   ex+=['break *'+hex(int(base,16)+syms['encbound_eh_personality']),'continue','set $private = $r8','disable 2',
        'break *'+hex(int(base,16)+syms['__encbound_app_eh_match']),'continue','set $rdi = $private','disable 3']
   action=0;origin='__encbound_app_eh_match'
  else:
   ex+=['break *'+hex(int(base,16)+syms['private_read']),'continue']
   if case=='sdk-tls':
    # get_thread_data from the pinned SIM binary: fs:8 -> * -> *.
    ex+=['set $a = *(unsigned long*)($fs_base+8)','set $b = *(unsigned long*)$a',
         'set $td = *(unsigned long*)$b','set $private = *(unsigned long*)($td+104)']
   else:
    ex+=['set $private = *(unsigned long*)'+hex(live)]
    if case=='unwind-header':
     ex+=['set $private = (unsigned long)&((__cxxabiv1::__cxa_exception*)$private)->unwindHeader']
   ex+=['set $rdi = $private','disable 2'];action=106;origin='private_read'
  ex+=['printf "INJECTED_PRIVATE %p\\n", $private','continue','printf "ABORT_CODE %d\\n", $edi','bt']
  command=['gdb','-q','-batch',*[v for c in ex for v in ('-ex',c)],'--args',str(out/'host'),str(out/'enclave.signed.so'),str(action)]
  p=subprocess.run(command,env=dict(os.environ,LD_LIBRARY_PATH=str(S/'sdk_libs')+':'+str(S/'lib64'),ENCBOUND_TEST_BASE=base),text=True,capture_output=True,timeout=60)
  text=p.stdout+p.stderr;log=B/f'private-{profile}-{base}-{case}.log';log.write_text(text)
  assert p.returncode==0 and 'ABORT_CODE 3\n' in text and 'encbound_require' in text and origin in text and 'INJECTED_PRIVATE 0x' in text,(case,text)
  rows.append(dict(profile=profile,base=base,case=case,mode='SDK SIM / GDB pointer-argument injection',abort_code=3,result='pass',log=str(log),image_sha256=hashlib.sha256((out/'enclave.signed.so').read_bytes()).hexdigest()))
  print(profile,base,case,'POLICY attributed',flush=True)
(B/'private-protection.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX EH PRIVATE STATE PROTECTION PASS',len(rows))
