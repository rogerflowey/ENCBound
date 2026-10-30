#!/usr/bin/env python3
"""Late fast guards: independent verifier mutations and native real runtime."""
from pathlib import Path
import json, re, subprocess
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/pass/fast-paths';OUT.mkdir(parents=True,exist_ok=True)
PLUGIN=ROOT/'build/pass/encbound_pass.so'
HEADER='target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"\ntarget triple = "x86_64-pc-linux-gnu"\n'
results=[]
def opt(name,body,mode='loops',verify=False,reject=False):
 src=OUT/(name+'.ll');src.write_text(body)
 subprocess.run(['opt-21','-passes=verify','-disable-output',str(src)],check=True,capture_output=True)
 dst=OUT/(name+'.out.ll')
 pipeline='encbound-fast-verify' if verify else 'encbound,encbound-verify,encbound-reuse,encbound-verify,encbound-fast,encbound-fast-verify,verify'
 p=subprocess.run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes='+pipeline,'-encbound-check-reuse=loop','-encbound-fast-paths='+mode,'-S',str(src),'-o',str(dst)],text=True,capture_output=True)
 (OUT/(name+'.log')).write_text(p.stdout+p.stderr)
 assert (p.returncode!=0)==reject,(name,p.stderr)
 if reject:assert 'ENCBound:' in p.stderr,(name,p.stderr)
 results.append(name)
 return dst.read_text() if not reject else ''
PAIR=HEADER+'''define i64 @pair(ptr %p, i64 %offset) {
entry:
 %a = load i64, ptr %p
 %q = getelementptr i8, ptr %p, i64 %offset
 %b = load i64, ptr %q, align 1
 %r = add i64 %a, %b
 ret i64 %r
}
'''
LOOP=HEADER+'''define i64 @fill(ptr %p, i64 %start, i64 %end) {
entry:
 %empty = icmp eq i64 %start, %end
 br i1 %empty, label %exit, label %pre
pre:
 br label %body
body:
 %i = phi i64 [%start, %pre], [%next, %body]
 %acc = phi i64 [0, %pre], [%sum, %body]
 %q = getelementptr i64, ptr %p, i64 %i
 store i64 %i, ptr %q, align 1
 %sum = add i64 %acc, %i
 %next = add i64 %i, 1
 %done = icmp eq i64 %next, %end
 br i1 %done, label %exit, label %body
exit:
 %result = phi i64 [0, %entry], [%sum, %body]
 ret i64 %result
}
'''
for mode in ['off','inline','loops']:
 pair=opt('pair-'+mode,PAIR,mode)
 loop=opt('loop-'+mode,LOOP,mode)
 assert ('!encbound.inline' in pair)==(mode!='off')
 assert ('!encbound.loop' in loop)==(mode=='loops')
# Inline predicates, geometry and raw values cannot be authorized by metadata.
valid=opt('inline-base',PAIR,'inline')
mutations={
 'inline-always':re.sub(r'br i1 %[^,]+, label %encbound.inline.hit', 'br i1 true, label %encbound.inline.hit',valid,count=1),
 'inline-width':valid.replace('i64 8, i32 1,','i64 4, i32 1,',1),
 'inline-kind':valid.replace('i64 8, i32 1,','i64 8, i32 2,',1),
 'inline-radix':valid.replace('lshr i64 %encbound.cap, 59','lshr i64 %encbound.cap, 58'),
 'inline-poison':valid.replace('sub i64','sub nuw i64',1),
 'inline-missing-markers':re.sub(r', !encbound.inline !\d+','',valid),
 'inline-volatile':valid.replace('load i64','load volatile i64'),
 'inline-unused-raw-load':valid.replace('ret i64 %r','%unauthorized = load i64, ptr %p\n  ret i64 %r'),
 'inline-forged-token':re.sub(r'i64 %encbound.span.token[\w.]*', 'i64 42',valid),
}
# Do not depend on LLVM's numeric suffixes.
token=re.search(r'(%[\w.]+) = call i64 @encbound_span_prepare',valid).group(1)
mutations['inline-forged-token']=valid.replace('i64 '+token,'i64 42')
firstshift=re.search(r'lshr i64 [^,]+, 59',valid).group(0)
mutations['inline-radix']=valid.replace(firstshift,firstshift[:-2]+'58',1)
rawline=re.search(r'(%encbound.inline.raw[^ ]*) = add i64 ([^,]+), ([^\n]+)',valid)
mutations['inline-raw']=valid.replace(rawline.group(0),rawline.group(1)+' = add i64 '+rawline.group(2)+', 0',1)
mutations['inline-escape']=valid.replace('ret i64 %r','ret i64 %encbound.inline.result')
for name,s in mutations.items():
 assert s!=valid,name
 opt(name,s,verify=True,reject=True)
valid=opt('loop-base',LOOP)
mutations={
 'loop-always':re.sub(r'br i1 %[^,]+, label %encbound.loop.hit','br i1 true, label %encbound.loop.hit',valid,count=1),
 'loop-trip':valid.replace('icmp ugt i64 %end, %start','icmp uge i64 %end, %start',1),
 'loop-range':valid.replace('icmp ule i64','icmp uge i64',1),
 'loop-store':valid.replace('store i64 %i.encbound.fast,','store i64 99,'),
 'loop-increment':valid.replace('add i64 %i.encbound.fast, 1','add i64 %i.encbound.fast, 2'),
 'loop-marker':re.sub(r', !encbound.loop !\d+','',valid),
 'loop-flags':valid.replace('add i64 %i.encbound.fast, 1','add nuw i64 %i.encbound.fast, 1'),
 'loop-exit':valid.replace('[ %sum.encbound.fast, %body.encbound.fast ]','[ 42, %body.encbound.fast ]'),
}
for name,s in mutations.items():
 assert s!=valid,name
 opt(name,s,verify=True,reject=True)
# Refuse non-affine accesses, volatile and barriers. Positive non-unit step.
nonaffine=LOOP.replace('i64 %i\n store','i64 %acc\n store')
assert '!encbound.loop' not in opt('nonaffine',nonaffine)
assert '!encbound.loop' not in opt('volatile',LOOP.replace('store i64','store volatile i64'))
barrier=LOOP.replace(' %sum =',' call void @barrier()\n %sum =')+'define void @barrier() { ret void }\n'
assert '!encbound.loop' not in opt('barrier',barrier)
step=LOOP.replace('@fill(', '@fill4(').replace('%next = add i64 %i, 1','%next = add i64 %i, 4')
assert '!encbound.loop' in opt('step4',step)
# Narrowing a capability or using a decreasing affine index is not an admitted
# loop proof. These keep the independently verified inline fallback guards.
truncated=LOOP.replace(' %q = getelementptr i64, ptr %p, i64 %i',
 ' %lo = trunc i64 %i to i32\n %wide = zext i32 %lo to i64\n %q = getelementptr i64, ptr %p, i64 %wide')
assert '!encbound.loop' not in opt('truncated-index',truncated)
negative=LOOP.replace(' %q = getelementptr i64, ptr %p, i64 %i',
 ' %neg = sub i64 0, %i\n %q = getelementptr i64, ptr %p, i64 %neg')
assert '!encbound.loop' not in opt('negative-stride',negative)
# Native checks link actual transformed objects to the real fake-platform runtime.
harness=OUT/'harness.c';harness.write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "encbound_runtime.h"
#include "fake_platform.h"
extern uint64_t fill(void*,uint64_t,uint64_t),fill4(void*,uint64_t,uint64_t),pair(void*,uint64_t);
int main(void) {
 assert(encbound_runtime_init_with_key(1,2)==0);
 assert(fill((void*)UINT64_MAX,0,0)==0); /* zero-trip invalid pointer */
 void *p=encbound_malloc(128);assert(p);
 uintptr_t raw=encbound_require((uintptr_t)p,128,3);uint64_t *a=(void*)raw;
 for(unsigned n=0;n<=16;n++) for(unsigned start=0;start<=n;start++) {
  memset(a,0x5a,128);assert(fill(p,start,n)==(n*(n-1)-start*(start-1))/2);
  for(unsigned i=0;i<16;i++)assert(a[i]==(i>=start&&i<n ? i : UINT64_C(0x5a5a5a5a5a5a5a5a)));
 }
 assert(fill4(p,0,16)==24);for(unsigned i=0;i<16;i+=4)assert(a[i]==i);
 a[0]=17;a[15]=19;assert(pair(p,120)==36);
 fake_abort_active=1;
 /* Valid prepare of p; corrupted candidate must miss its inline guard. */
 for(unsigned j=0;j<3;j++) {
  uint64_t off=j==0?124:j==1?(UINT64_C(1)<<32):UINT64_MAX-3;
  if(!setjmp(fake_abort_env)){pair(p,off);assert(0);}
  uintptr_t ignored;int expected=encbound_check((uintptr_t)p+off,8,1,&ignored);
  assert(expected!=0&&fake_abort_code==expected);
 }
 /* Failed preflight must not abort early: valid prefix stores still execute. */
 memset(a,0x5a,128);
 if(!setjmp(fake_abort_env)){fill((void*)((uintptr_t)p+4),0,16);assert(0);}assert(fake_abort_code==4);
 for(unsigned i=0;i<15;i++){uint64_t v;memcpy(&v,(char*)a+4+8*i,8);assert(v==i);}
 a[15]=UINT64_MAX;
 if(!setjmp(fake_abort_env)){fill((void*)((uintptr_t)p+124),0,1);assert(0);}
 assert(fake_abort_code==4&&a[15]==UINT64_MAX);
 /* Enormous end, nondivisible end and modular induction never authorize fast. */
 if(!setjmp(fake_abort_env)){fill((void*)((uintptr_t)p+4),0,UINT64_MAX);assert(0);}assert(fake_abort_code==4);
 if(!setjmp(fake_abort_env)){fill4((void*)((uintptr_t)p+124),0,3);assert(0);}assert(fake_abort_code==4);
 if(!setjmp(fake_abort_env)){fill(p,UINT64_MAX,2);assert(0);}assert(fake_abort_code==3);
 fake_abort_active=0;encbound_free(p);puts("FAST EXECUTION PASS: outputs, zero trip, partial prefix, boundaries and overflow");
}
''')
# RADIX_ONLY deliberately ignores the tag, and must accept this same-slot access.
s=harness.read_text().replace('if(!setjmp(fake_abort_env)){pair(p,off);assert(0);}', '''
#ifndef ENCBOUND_MAC27
  if(j==1){assert(pair(p,off)==34);continue;}
#endif
  if(!setjmp(fake_abort_env)){pair(p,off);assert(0);}''');harness.write_text(s)
rt=[ROOT/'runtime'/f'{x}.c' for x in ['check_core','allocations','allocator','adapters']]+[ROOT/'tests/fake_platform.c']
for profile in ['RADIX_ONLY','MAC27']:
 flags=['-I'+str(ROOT/p) for p in ['include','runtime','tests']]+(['-DENCBOUND_MAC27'] if profile=='MAC27' else [])
 for mode in ['inline','loops']:
  for cg in ['-O0','-O2']:
   objects=[]
   for name in ['pair-'+mode,'loop-'+mode,'step4']:
    obj=OUT/(name+cg+'.o');objects.append(obj)
    subprocess.run(['clang-21',cg,'-Xclang','-disable-llvm-passes','-c',str(OUT/(name+'.out.ll')),'-o',str(obj)],check=True)
   exe=OUT/(profile+'-'+mode+cg)
   subprocess.run(['cc','-O2',*flags,str(harness),*map(str,objects),*map(str,rt),'-o',str(exe)],check=True)
   p=subprocess.run([str(exe)],capture_output=True,text=True,timeout=20)
   (OUT/(exe.name+'.log')).write_text(p.stdout+p.stderr)
   assert p.returncode==0,(exe,p.stderr)
   results.append(exe.name)
(OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print('FAST PATH TESTS PASS',len(results),'groups')
