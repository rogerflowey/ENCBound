#!/usr/bin/env python3
"""Execute checked atomic IR with the real runtime; failures must precede writes."""
from pathlib import Path
import json,os,subprocess
R=Path(__file__).resolve().parents[2];B=R/'build/integration/atomics';B.mkdir(parents=True,exist_ok=True)
# Pass admission/verifier fixtures are also the runtime's operation definitions.
subprocess.run(['python3',R/'tests/pass/atomic_virtual_test.py'],check=True)
decls=[];checks=[]
for n in (8,16,32,64):
 t=f'uint{n}_t'
 decls += [f'{t} load{n}(void*); void store{n}(void*,{t}); {t} add{n}(void*,{t}); {t} cas{n}(void*,{t},{t}); void fence{n}(void);']
 checks += [f'''store{n}(p,10);assert(load{n}(p)==10);
 assert(add{n}(p,3)==10);assert(load{n}(p)==13);
 assert(cas{n}(p,13,21)==13);assert(load{n}(p)==21);
 assert(cas{n}(p,13,22)==21);assert(load{n}(p)==21);fence{n}();''']
src=B/'harness.c';src.write_text('''#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
'''+ '\n'.join(decls)+'''
static void reject(void *bad, int code) {
 fake_abort_active=1;
 if (!setjmp(fake_abort_env)) {add64(bad,999);assert(0);}
 assert(fake_abort_code==code);
 if (!setjmp(fake_abort_env)) {cas64(bad,21,999);assert(0);}
 assert(fake_abort_code==code);
 if (!setjmp(fake_abort_env)) {store64(bad,999);assert(0);}
 assert(fake_abort_code==code);
 if (!setjmp(fake_abort_env)) {load64(bad);assert(0);}
 assert(fake_abort_code==code);fake_abort_active=0;
}
int main(void) {
 assert(encbound_runtime_init_with_key(11,22)==0);
 void *p=encbound_malloc(16);assert(p);
 uint64_t *raw=(uint64_t*)encbound_require((uintptr_t)p,16,ENCBOUND_ACCESS_READWRITE);
'''+ '\n'.join(checks)+'''
 raw[0]=21;raw[1]=21;
 // Synthetic corrupted capability crosses the 16-byte slot. No memory op may run.
 reject((void*)((uintptr_t)p+12),ENCBOUND_ERR_RANGE);
 assert(raw[0]==21 && raw[1]==21);
 // Stripping a capability cannot authorize access to the protected heap.
 reject(raw,ENCBOUND_ERR_POLICY);
 assert(raw[0]==21 && raw[1]==21);
#ifdef ENCBOUND_MAC27
 reject((void*)((uintptr_t)p ^ (UINT64_C(1)<<32)),ENCBOUND_ERR_TAG);
 assert(raw[0]==21 && raw[1]==21);
#endif
 encbound_free(p);puts("ATOMIC NATIVE REAL-RUNTIME PASS");
}
''')
rows=[]
for profile in ('RADIX_ONLY','MAC27'):
 for opt in ('-O0','-O2'):
  objects=[]
  for bits in (8,16,32,64):
   srcir=R/f'build/pass/atomic-virtual/positive{bits}.ll';ir=B/f'{profile}-{bits}.ll';obj=B/f'{profile}-{bits}-{opt[1:]}.o'
   subprocess.run(['opt-21','-load-pass-plugin='+str(R/'build/pass/encbound_pass.so'),'-encbound-atomics','-encbound-profile='+profile,'-passes=encbound,encbound-verify,verify','-S',srcir,'-o',ir],check=True)
   subprocess.run(['clang-21',opt,'-Xclang','-disable-llvm-passes','-c',ir,'-o',obj],check=True);objects.append(obj)
  exe=B/f'{profile}-{opt[1:]}'
  cmd=['clang-21','-O2','-I'+str(R/'include'),'-I'+str(R/'runtime'),'-I'+str(R/'tests')]
  if profile=='MAC27':cmd+=['-DENCBOUND_MAC27']
  cmd += [R/'runtime'/f for f in ('siphash.c','runtime.c','capability.c','allocator.c','allocations.c')]+[R/'tests/fake_platform.c',src,*objects,'-o',exe]
  subprocess.run(cmd,check=True)
  p=subprocess.run([exe],capture_output=True,text=True);(B/f'{profile}-{opt[1:]}.log').write_text(p.stdout+p.stderr)
  assert p.returncode==0,(profile,opt,p.stderr)
  rows.append(dict(profile=profile,codegen=opt,result='pass',mode='native fake platform, real runtime',negative_operations=['load','store','rmw','cmpxchg']))
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('ATOMIC REAL-RUNTIME MATRIX PASS',len(rows),'configurations')
