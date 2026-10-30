#!/usr/bin/env python3
"""Guarded reuse: compiler scopes, validator mutations and real native runtime."""
from pathlib import Path
import subprocess, os, re, json
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/pass/reuse'; OUT.mkdir(parents=True,exist_ok=True)
PLUGIN=ROOT/'build/pass/encbound_pass.so'
HEADER='target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"\ntarget triple = "x86_64-pc-linux-gnu"\n'
results=[]
def opt(name,body,mode='loop',verify=False,reject=False):
    src=OUT/(name+'.ll'); src.write_text(body)
    subprocess.run(['opt-21','-passes=verify','-disable-output',str(src)],check=True)
    dst=OUT/(name+'.out.ll')
    pipeline='encbound-verify,verify' if verify else 'encbound,encbound-verify,encbound-reuse,encbound-verify,verify'
    p=subprocess.run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes='+pipeline,'-encbound-check-reuse='+mode,'-S',str(src),'-o',str(dst)],text=True,capture_output=True)
    (OUT/(name+'.log')).write_text(p.stdout+p.stderr)
    assert (p.returncode!=0)==reject,(name,p.stderr)
    if reject: assert 'ENCBound:' in p.stderr,(name,p.stderr)
    results.append(name)
    return dst.read_text() if not reject else ''
body=HEADER+'''define i64 @pair(ptr %p) {
entry:
 %a = load i64, ptr %p
 %q = getelementptr i64, ptr %p, i64 1
 %b = load i64, ptr %q
 %c = add i64 %a, %b
 ret i64 %c
}
'''
for mode in ['off','block','loop']:
    out=opt('pair-'+mode,body,mode)
    assert out.count('call i64 @encbound_span_prepare')==(0 if mode=='off' else 1)
    assert out.count('call i64 @encbound_span_require')==(0 if mode=='off' else 2)
valid=opt('mutation-base',body,'block')
# Each mutation remains LLVM-valid; require an ENCBound rejection.
span=re.search(r'  (%[\w.]+) = call i64 @encbound_span_require\(([^\n]+)\)',valid)
token=re.search(r'(%[\w.]+) = call i64 @encbound_span_prepare',valid).group(1)
anchor=re.search(r'call i64 @encbound_span_prepare\(i64 ([^)]+)\)',valid).group(1)
mutations={
 'forged-token':valid.replace(', i64 '+token+')',', i64 42)'),
 'wrong-anchor':valid.replace(', i64 '+anchor+', i64 '+token,', i64 42, i64 '+token),
 'wrong-width':valid.replace('i64 8, i32 1,','i64 4, i32 1,'),
 'wrong-kind':valid.replace('i64 8, i32 1,','i64 8, i32 2,'),
 'volatile':valid.replace('load i64','load volatile i64'),
 'token-return':valid.replace('ret i64 %c','ret i64 '+token),
 'token-arithmetic':valid.replace('ret i64 %c','%escape = add i64 '+token+', 1\n  ret i64 %escape'),
 'barrier':valid.replace(span.group(0),'  call void @barrier()\n'+span.group(0))+'\ndeclare void @barrier()\n',
 'token-call-escape':valid.replace(span.group(0),'  call void @sink(i64 '+token+')\n'+span.group(0))+'\ndeclare void @sink(i64)\n',
 'token-store':valid.replace(span.group(0),'  store i64 '+token+', ptr %p\n'+span.group(0)),
 'unverified-cfg':valid.replace(span.group(0),'  br label %other\nother:\n'+span.group(0)),
 'raw-return':valid.replace('ret i64 %c','ret i64 '+span.group(1)),
}
for name,s in mutations.items(): opt(name,s,verify=True,reject=True)
# Calls and volatile operations split sharing; loaded pointers are fresh origins.
barrier=body.replace(' %q =',' call void @barrier()\n %q =')+'declare void @barrier()\n'
# Source admission requires a known cross-unit function; a same-module body suffices.
barrier=barrier.replace('declare void @barrier()','define void @barrier() { ret void }')
for name,s in [('call-barrier',barrier),('volatile-barrier',body.replace(' %q =',' %v = load volatile i64, ptr %p\n %q ='))]:
    out=opt(name,s); assert 'call i64 @encbound_span_prepare' not in out
reload=HEADER+'''define i64 @reload(ptr %pp) {
 %p = load ptr, ptr %pp
 %a = load i64, ptr %p
 %q = load ptr, ptr %pp
 %b = load i64, ptr %q
 %c = add i64 %a, %b
 ret i64 %c
}
'''
out=opt('pointer-reload',reload); assert out.count('call i64 @encbound_span_require')==2 # pp only
loop=HEADER+'''define void @fill(ptr %p, i64 %n) {
entry:
 br label %head
head:
 %i = phi i64 [0, %entry], [%next, %body]
 %more = icmp ult i64 %i, %n
 br i1 %more, label %body, label %exit
body:
 %q = getelementptr i64, ptr %p, i64 %i
 store i64 %i, ptr %q
 %next = add i64 %i, 1
 br label %head
exit:
 ret void
}
'''
out=opt('loop',loop); assert out.count('call i64 @encbound_span_prepare')==1
assert out.index('call i64 @encbound_span_prepare')<out.index('head:')
mut=out.replace('  store i64', '  call void @barrier()\n  store i64')+'\ndeclare void @barrier()\n'
opt('loop-barrier-mutation',mut,verify=True,reject=True)
opt('source-helper-call',HEADER+'declare i64 @encbound_span_prepare(i64)\ndefine i64 @f(i64 %p) { %x = call i64 @encbound_span_prepare(i64 %p)\n ret i64 %x }',reject=True)
# Actual transformed loop linked to real fake-platform runtime at both codegen levels.
harness=OUT/'harness.c'; harness.write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "encbound_runtime.h"
#include "fake_platform.h"
extern void fill(void*,uint64_t);
int main(void) {
 assert(encbound_runtime_init_with_key(1,2)==0);
 fill((void*)UINT64_MAX,0); /* invalid speculative prepare must not abort */
 void *p=encbound_malloc(128); assert(p);
 uintptr_t raw=encbound_require((uintptr_t)p,128,3);
 fill(p,16); for(unsigned i=0;i<16;i++) assert(((uint64_t*)raw)[i]==i);
 fake_abort_active=1;
 /* Interior pointer: the final store straddles the slot edge. */
 ((unsigned char*)raw)[127]=0xa5;
 if(!setjmp(fake_abort_env)) { fill((void*)((uintptr_t)p+124),1); assert(0); }
 assert(fake_abort_code==4 && ((unsigned char*)raw)[127]==0xa5);
 fake_abort_active=0;
 encbound_free(p); puts("REUSE EXECUTION PASS: zero trip, output, rejection before store");
}
''')
rt=[ROOT/'runtime'/f'{x}.c' for x in ['check_core','allocations','allocator','adapters']]+[ROOT/'tests/fake_platform.c']
for profile in ['RADIX_ONLY','MAC27']:
    flags=['-I'+str(ROOT/p) for p in ['include','runtime','tests']]+(['-DENCBOUND_MAC27'] if profile=='MAC27' else [])
    for cg in ['-O0','-O2']:
        obj=OUT/(profile+cg+'.o')
        subprocess.run(['clang-21',cg,'-Xclang','-disable-llvm-passes','-c',str(OUT/'loop.out.ll'),'-o',str(obj)],check=True)
        exe=OUT/(profile+cg)
        subprocess.run(['cc','-O2',*flags,str(harness),str(obj),*map(str,rt),'-o',str(exe)],check=True)
        p=subprocess.run([str(exe)],capture_output=True,text=True,check=True,timeout=20)
        (OUT/(exe.name+'.log')).write_text(p.stdout+p.stderr);results.append(exe.name)
    for sanitizer in [False,True]:
        exe=OUT/(profile+'-corpus'+('-san' if sanitizer else ''))
        subprocess.run(['clang-21','-O2',*(['-fsanitize=address,undefined','-fno-sanitize-recover=all'] if sanitizer else []),*flags,str(ROOT/'tests/span_runtime_test.c'),*map(str,rt),'-o',str(exe)],check=True)
        p=subprocess.run([str(exe)],capture_output=True,text=True,check=True,timeout=30)
        (OUT/(exe.name+'.log')).write_text(p.stdout+p.stderr);results.append(exe.name)
(OUT/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print('REUSE TESTS PASS',len(results),'groups')
