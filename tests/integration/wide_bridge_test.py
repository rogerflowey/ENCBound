#!/usr/bin/env python3
"""Execute generated narrow/wide OCALL result stores, signed/length admission."""
from pathlib import Path
import os,subprocess,json
R=Path(__file__).resolve().parents[2];O=R/'build/integration/wide-bridge';O.mkdir(parents=True,exist_ok=True)
SDK=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
GEN=R/'build/edger8r/sgx_edger8r'
(O/'interface.json').write_text('{"records":{},"sdk_only_imports":{}}')
(O/'wide.edl').write_text('''enclave { trusted { public void enter(); }; untrusted { uint8_t byte_result(); uint64_t wide_result(); }; };''')
flags=['-I'+str(p) for p in (SDK/'include',R/'tests/fixtures/modified_bridge',R/'include',R/'runtime',R/'sdk',R/'tests')]
source=r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
int bridge_copy_fail;
#include "wide_t.c"
static void *buffer;
static int transport_error;
void enter(void) {}
int sgx_is_outside_enclave(const void *p,size_t n) { (void)n;return p!=NULL; }
int sgx_is_within_enclave(const void *p,size_t n) {
 uintptr_t a=(uintptr_t)p,b=encbound_enclave_base();
#ifdef ENCBOUND_PROTECTED
 return a>=b && a-b<encbound_enclave_size() && n<=encbound_enclave_size()-(a-b);
#else
 return p!=NULL;
#endif
}
void *sgx_ocalloc(size_t n) {assert(!buffer);return buffer=malloc(n);}
void sgx_ocfree(void) {free(buffer);buffer=0;}
sgx_status_t sgx_ocall(unsigned index,void *m) {
 if(transport_error)return SGX_ERROR_UNEXPECTED;
 if(index==0)((ms_byte_result_t*)m)->ms_retval=UINT8_MAX;
 else ((ms_wide_result_t*)m)->ms_retval=UINT64_MAX;
 return SGX_SUCCESS;
}
int main(void) {
#ifdef ENCBOUND_PROTECTED
 assert(encbound_runtime_init_with_key(1,2)==0);
 unsigned char *p=encbound_malloc(16);
 unsigned char *raw=(void*)encbound_require((uintptr_t)p,16,3);
#else
 unsigned char *p=malloc(16),*raw=p;
#endif
 memset(raw,0x5a,16);
 assert(byte_result(p+15)==SGX_SUCCESS && raw[14]==0x5a && raw[15]==255);
 assert(wide_result((uint64_t*)(p+8))==SGX_SUCCESS);
 uint64_t v;memcpy(&v,raw+8,8);assert(v==UINT64_MAX && raw[7]==0x5a);
 transport_error=1;raw[15]=0x11;
 assert(byte_result(p+15)==SGX_ERROR_UNEXPECTED && raw[15]==0x11 && !buffer);
 transport_error=0;
#ifdef ENCBOUND_PROTECTED
 fake_abort_active=1;
 if(!setjmp(fake_abort_env)){wide_result((uint64_t*)(p+15));assert(0);}
 assert(fake_abort_code==ENCBOUND_ERR_RANGE);fake_abort_active=0;
 encbound_free(p);
#else
 free(p);
#endif
 return 0;
}
'''
(O/'test.c').write_text(source)
for profile in ('BASELINE','RADIX_ONLY','MAC27'):
 out=O/profile
 cmd=['python3',str(R/'tools/modified_bridge.py'),'--wide-scalars','--edl',str(O/'wide.edl'),'--interface',str(O/'interface.json'),'--generator',str(GEN),'--out-dir',str(out),'--profile',profile]+['--cflag='+f for f in flags]
 subprocess.run(cmd,check=True,capture_output=True)
 if profile=='BASELINE':
  stock=O/'stock';stock.mkdir(exist_ok=True)
  subprocess.run([SDK/'bin/x64/sgx_edger8r','--trusted','--trusted-dir',stock,'--untrusted','--untrusted-dir',stock,O/'wide.edl'],check=True,capture_output=True)
  for f in ('wide_t.c','wide_t.h','wide_u.c','wide_u.h'):assert (stock/f).read_bytes()==(out/f).read_bytes()
 cc=['clang-21','-O1',*flags,'-I'+str(out)]
 if profile!='BASELINE':cc+=['-DENCBOUND_PROTECTED']
 if profile=='MAC27':cc+=['-DENCBOUND_MAC27']
 cc += [str(O/'test.c'),str(R/'tests/fake_platform.c'),str(R/'sdk/boundary_support.c')]
 cc += [str(R/'runtime'/f) for f in ('siphash.c','runtime.c','capability.c','allocations.c','allocator.c','adapters.c')]
 cc+=['-o',str(out/'test')];subprocess.run(cc,check=True);subprocess.run([out/'test'],check=True)
# Ordinary scalar/length admission no longer depends on --wide-scalars.
(O/'signed.edl').write_text('enclave { trusted { public void entry([in,size=n] uint8_t *p, int64_t n); }; };')
p=subprocess.run(['python3',str(R/'tools/modified_bridge.py'),'--edl',str(O/'signed.edl'),'--interface',str(O/'interface.json'),'--generator',str(GEN),'--out-dir',str(O/'signed'),'--profile','MAC27']+['--cflag='+f for f in flags],text=True,capture_output=True)
assert p.returncode == 0, p.stderr
print('WIDE BRIDGE PASS (all profiles, exact return width, transport failure, range rejection, stock equivalence)')
