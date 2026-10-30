#!/usr/bin/env python3
"""Bounded local-proof admission, independent mutations and executable checks."""
from pathlib import Path
import json,subprocess
ROOT=Path(__file__).resolve().parents[2];OUT=ROOT/'build/pass/local-proofs';OUT.mkdir(parents=True,exist_ok=True)
HEADER='target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"\ntarget triple = "x86_64-pc-linux-gnu"\n'
results=[]
def run(name,body,verify=False,reject=False,reuse='off',enabled=True):
 src=OUT/(name+'.ll');dst=OUT/(name+'.out.ll');src.write_text(body)
 subprocess.run(['opt-21','-passes=verify','-disable-output',str(src)],check=True)
 pipeline='encbound-verify,verify' if verify else 'encbound,encbound-verify,encbound-reuse,encbound-verify,encbound-local-proofs,encbound-verify,verify'
 p=subprocess.run(['opt-21','-load-pass-plugin='+str(ROOT/'build/pass/encbound_pass.so'),'-passes='+pipeline,'-encbound-local-proofs='+str(int(enabled)),'-encbound-check-reuse='+reuse,'-S',str(src),'-o',str(dst)],text=True,capture_output=True)
 (OUT/(name+'.log')).write_text(p.stdout+p.stderr)
 assert (p.returncode!=0)==reject,(name,p.stderr)
 if reject:assert 'ENCBound: validation failed' in p.stderr,(name,p.stderr)
 results.append(name);return '' if reject else dst.read_text()
SOURCE=HEADER+'''define i64 @repeat(ptr %p) {
 %a = load i64, ptr %p
 %q = getelementptr i8, ptr %p, i64 4
 %b = load i32, ptr %q
 %x = zext i32 %b to i64
 %v = add i64 %a, %x
 ret i64 %v
}
define i64 @local() {
 %p = alloca [2 x i64], align 16
 %q = getelementptr i8, ptr %p, i64 8
 store i64 37, ptr %q
 %a = load i64, ptr %q
 ret i64 %a
}
'''
for reuse in ['off','block','loop']:
 out=run('positive-'+reuse,SOURCE,reuse=reuse)
 assert out.count('call i64 @encbound_require')+out.count('call i64 @encbound_span_require')==1
 assert out.count('call i64 @encbound_stack_mint')==1 and 'encbound.proven.local' in out
 assert 'add i64' in out
run('disabled',SOURCE,enabled=False)
STORE=HEADER+'''define void @covered_store(ptr %p) {
 store i64 42, ptr %p
 %q = getelementptr i8, ptr %p, i64 4
 store i32 9, ptr %q
 ret void
}
'''
for reuse in ['off','loop']:
 out=run('stores-'+reuse,STORE,reuse=reuse)
 assert out.count('call i64 @encbound_require')+out.count('call i64 @encbound_span_require')==1

# Independent hand-written valid output, without transform metadata or magic names.
CHECK=HEADER+'''declare i64 @encbound_require(i64, i64, i32)
define i64 @f(i64 %p) {
entry:
 %r = call i64 @encbound_require(i64 %p, i64 8, i32 1)
 %a = inttoptr i64 %r to ptr
 %x = load i64, ptr %a
 %s = add i64 %r, 4
 %b = inttoptr i64 %s to ptr
 %y = load i32, ptr %b
 ret i64 %x
}
'''
LOCAL=HEADER+'''declare i64 @encbound_stack_mint(ptr, i64)
define i64 @f() {
entry:
 %slot = alloca i8, i64 16, align 16
 %cap = call i64 @encbound_stack_mint(ptr %slot, i64 16)
 %raw = ptrtoint ptr %slot to i64
 %r = add i64 %raw, 8
 %a = inttoptr i64 %r to ptr
 store i64 99, ptr %a
 %b = inttoptr i64 %r to ptr
 %v = load i64, ptr %b
 ret i64 %v
}
'''
run('independent-check',CHECK,verify=True);run('independent-local',LOCAL,verify=True)
run('proofs-disabled-check',CHECK,verify=True,reject=True,enabled=False)
run('proofs-disabled-local',LOCAL,verify=True,reject=True,enabled=False)
mutations={
 'check-overshoot':CHECK.replace('add i64 %r, 4','add i64 %r, 5'),
 'check-negative':CHECK.replace('add i64 %r, 4','add i64 %r, -1'),
 'check-width':CHECK.replace('i64 8, i32 1','i64 4, i32 1'),
 'check-kind':CHECK.replace('i64 8, i32 1','i64 8, i32 2'),
 'raw-return':CHECK.replace('ret i64 %x','ret i64 %r'),
 'raw-call':CHECK.replace(' %s =',' call void @escape(i64 %r)\n %s =')+'declare void @escape(i64)\n',
 'check-barrier':CHECK.replace(' %s =',' call void @barrier()\n %s =')+'declare void @barrier()\n',
 'check-volatile':CHECK.replace('load i32','load volatile i32'),
 'check-cfg':CHECK.replace(' %s =',' br label %next\nnext:\n %s ='),
 'local-overshoot':LOCAL.replace('add i64 %raw, 8','add i64 %raw, 9'),
 'local-negative':LOCAL.replace('add i64 %raw, 8','add i64 %raw, -1'),
 'local-no-mint':LOCAL.replace(' %cap = call i64 @encbound_stack_mint(ptr %slot, i64 16)\n',''),
 'local-size':LOCAL.replace('ptr %slot, i64 16','ptr %slot, i64 32'),
 'local-alignment':LOCAL.replace('align 16','align 8'),
 'local-return':LOCAL.replace('ret i64 %v','ret i64 %raw'),
 'local-slot-escape':LOCAL.replace('ret i64 %v','call void @escape(ptr %slot)\n ret i64 %v')+'declare void @escape(ptr)\n',
 'local-barrier':LOCAL.replace(' %raw =',' call void @barrier()\n %raw =')+'declare void @barrier()\n',
 'local-volatile':LOCAL.replace('load i64','load volatile i64'),
 'local-nsw':LOCAL.replace('add i64 %raw','add nsw i64 %raw'),
 'local-dynamic-offset':LOCAL.replace('define i64 @f()','define i64 @f(i64 %n)').replace('add i64 %raw, 8','add i64 %raw, %n'),
}
for name,body in mutations.items():run(name,body,verify=True,reject=True)
# Barriers, unknown offsets and pointer reloads keep actual checks.
for name,body in {
 'call':SOURCE.replace(' %q = getelementptr i8, ptr %p, i64 4',' call void @barrier()\n %q = getelementptr i8, ptr %p, i64 4')+'define void @barrier() { ret void }\n',
 'volatile':SOURCE.replace('%b = load i32','%b = load volatile i32'),
 'out-of-range':SOURCE.replace('ptr %p, i64 4','ptr %p, i64 5'),
}.items():
 out=run('kept-'+name,body);assert out.count('call i64 @encbound_require')==2
RELOAD=HEADER+'''define i64 @reload(ptr %pp) {
 %p = load ptr, ptr %pp
 %a = load i64, ptr %p
 %q = load ptr, ptr %pp
 %b = load i64, ptr %q
 %x = add i64 %a, %b
 ret i64 %x
}
'''
out=run('reload',RELOAD);assert out.count('call i64 @encbound_require')==3
# Truncating pointer round-trips must never inherit the original authority.
for width in [8,16,32,128]:
 body=HEADER+f'''define i64 @narrow(ptr %p) {{
 %a = load i64, ptr %p
 %bits = ptrtoint ptr %p to i{width}
 %q = inttoptr i{width} %bits to ptr
 %b = load i64, ptr %q
 %r = add i64 %a, %b
 ret i64 %r
}}
'''
 for reuse in ['off','loop']:
  out=run(f'narrow-{width}-{reuse}',body,reuse=reuse)
  assert out.count('call i64 @encbound_require')+out.count('call i64 @encbound_span_require')==2
body=HEADER+'''define i64 @narrowlocal() {
 %p = alloca i64
 store i64 42, ptr %p
 %bits = ptrtoint ptr %p to i32
 %q = inttoptr i32 %bits to ptr
 %v = load i64, ptr %q
 ret i64 %v
}
'''
out=run('narrow-local',body);assert out.count('call i64 @encbound_require')==1
# Local code-generation test uses a diagnostic mint: it is not a runtime/SGX test.
h=OUT/'codegen.c';h.write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
static uint64_t data=0x1234567887654321ULL;static int checks,mints;
uint64_t encbound_require(uint64_t cap,uint64_t n,int k){assert(cap==0x12345678 && n==8 && k==1);checks++;return (uintptr_t)&data;}
uint64_t encbound_stack_mint(void *p,uint64_t n){assert(n==16 && !((uintptr_t)p&15));mints++;memset(p,0,n);return 0x7123456780000000ULL;}
extern uint64_t repeat(void*);extern uint64_t local(void);
int main(void){assert(repeat((void*)0x12345678)==data+0x12345678ULL);assert(checks==1);assert(local()==37 && mints==1 && checks==1);puts("LOCAL PROOF CODEGEN PASS");}
''')
for cg in ['-O0','-O2']:
 obj=OUT/(cg+'.o');exe=OUT/cg
 subprocess.run(['clang-21',cg,'-Xclang','-disable-llvm-passes','-c',str(OUT/'positive-off.out.ll'),'-o',str(obj)],check=True)
 subprocess.run(['cc','-O2',str(h),str(obj),'-o',str(exe)],check=True)
 p=subprocess.run([str(exe)],text=True,capture_output=True,check=True);(OUT/(cg+'.log')).write_text(p.stdout+p.stderr);results.append('codegen'+cg)
# Execute covered heap reads with the real runtime/fake platform, including
# malformed pointers and straddling ranges. No real-stack claim here.
h=OUT/'runtime.c';h.write_text(r''' 
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "encbound_runtime.h"
#include "encbound_internal.h"
#include "fake_platform.h"
extern uint64_t repeat(void*);
extern void covered_store(void*);
int main(void) {
 assert(encbound_runtime_init_with_key(1,2)==0);
 uintptr_t p=(uintptr_t)encbound_malloc(16),raw=encbound_require(p,16,3);
 uint64_t value=0x1234567887654321ULL;memcpy((void*)raw,&value,8);
 uintptr_t candidates[]={p,p+12,p^(1ULL<<32),raw,encbound_base()+0x300000,UINT64_MAX,0};
 for(unsigned i=0;i<7;i++) {
  uintptr_t decoded=0;int rc=encbound_check(candidates[i],8,1,&decoded);
  fake_abort_active=1;
  if(!setjmp(fake_abort_env)) {
   uint64_t got=repeat((void*)candidates[i]);assert(rc==0);
   uint64_t x;uint32_t y;memcpy(&x,(void*)decoded,8);memcpy(&y,(void*)(decoded+4),4);
   assert(got==x+y);
  } else assert(rc!=0 && fake_abort_code==rc);
  fake_abort_active=0;
 }
 for(unsigned i=0;i<7;i++) {
  memset((void*)raw,0xa5,16);
  uintptr_t decoded=0;int rc=encbound_check(candidates[i],8,2,&decoded);
  fake_abort_active=1;
  if(!setjmp(fake_abort_env)) {
   covered_store((void*)candidates[i]);assert(rc==0);
   uint64_t got;memcpy(&got,(void*)decoded,8);assert(got==0x90000002aULL);
  } else {
   assert(rc!=0 && fake_abort_code==rc);
   for(unsigned j=0;j<16;j++)assert(((unsigned char*)raw)[j]==0xa5);
  }
  fake_abort_active=0;
 }
 encbound_free((void*)p);puts("LOCAL PROOF REAL RUNTIME PASS");
}
''')
rt=[ROOT/'runtime'/f'{n}.c' for n in ['check_core','allocations','allocator','adapters']]+[ROOT/'tests/fake_platform.c']
for profile in ['RADIX_ONLY','MAC27']:
 for reuse in ['off','loop']:
  for cg in ['-O0','-O2']:
   name=profile+'-'+reuse+cg;obj=OUT/(name+'.o');exe=OUT/name
   subprocess.run(['clang-21',cg,'-Xclang','-disable-llvm-passes','-c',str(OUT/('positive-'+reuse+'.out.ll')),'-o',str(obj)],check=True)
   storeobj=OUT/(name+'-stores.o')
   subprocess.run(['clang-21',cg,'-Xclang','-disable-llvm-passes','-c',str(OUT/('stores-'+reuse+'.out.ll')),'-o',str(storeobj)],check=True)
   flags=['-I'+str(ROOT/p) for p in ['runtime','include','tests']]+(['-DENCBOUND_MAC27'] if profile=='MAC27' else [])
   subprocess.run(['clang-21','-O2','-fsanitize=address,undefined','-fno-sanitize-recover=all',*flags,str(h),str(obj),str(storeobj),*map(str,rt),'-o',str(exe)],check=True)
   p=subprocess.run([str(exe)],text=True,capture_output=True,check=True,timeout=20)
   (OUT/(name+'.log')).write_text(p.stdout+p.stderr);results.append(name)
# The narrowing counterexample must forward different full pointer bits to
# the two checks, not merely retain two calls with the same operand.
h=OUT/'narrow-execution.c';h.write_text(r'''
#include <stdint.h>
#include <assert.h>
static uint64_t data[]={1,2};static unsigned n;
uint64_t encbound_require(uint64_t p,uint64_t w,int k) {
 assert(n<2 && w==8 && k==1);
 assert(p==(n ? 0x8000ULL : 0x2123456700008000ULL));
 return (uintptr_t)&data[n++];
}
extern uint64_t narrow(void*);
int main(void){assert(narrow((void*)0x2123456700008000ULL)==3 && n==2);}
''')
for cg in ['-O0','-O2']:
 obj=OUT/('narrow'+cg+'.o');exe=OUT/('narrow'+cg)
 subprocess.run(['clang-21',cg,'-Xclang','-disable-llvm-passes','-c',str(OUT/'narrow-32-off.out.ll'),'-o',str(obj)],check=True)
 subprocess.run(['cc','-O2',str(h),str(obj),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True);results.append('narrow-execution'+cg)
(OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n');print('LOCAL PROOFS PASS',len(results),'groups')
