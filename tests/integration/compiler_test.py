#!/usr/bin/env python3
"""Step 16 compiler semantics, using an independent synthetic-capability oracle.
This is native compiler evidence, not an SGX protection result.
"""
from pathlib import Path
import os, subprocess, json
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'build/integration/compiler'
OUT.mkdir(parents=True, exist_ok=True)
PLUGIN = ROOT/'build/pass/encbound_pass.so'

def run(args, **kw):
    p = subprocess.run([str(a) for a in args], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)
    if p.returncode: raise AssertionError(p.stdout)
    return p.stdout

HEADER = '''#include <stddef.h>
#include <string.h>
struct Big { long a, b, c; long *p; };
struct Big change(struct Big x);
struct Big recursive(struct Big x, int n);
typedef long *(*Callback)(long *, long);
long *callback(long *p, long n);
Callback obtain(void);
'''
CALLEE = '''#include "api.h"
__attribute__((noinline)) struct Big change(struct Big x) {
  x.a += *x.p; x.b++; return x;
}
__attribute__((noinline)) long *callback(long *p, long n) { *p += n; return p; }
Callback obtain(void) { return callback; }
__attribute__((noinline)) struct Big recursive(struct Big x, int n) {
 x.a++; volatile long saved=x.a;
 if(n) { struct Big r=recursive(x,n-1); if(x.a!=saved) r.a=-99; return r; }
 return x;
}
'''
CALLER = '''#include "api.h"
static void *(*copy_table[])(void *, const void *, size_t) = {memcpy};
__attribute__((noinline)) static void *copy(void *(*f)(void *,const void *,size_t), void *d, const void *s) {
  return f(d,s,8);
}
__attribute__((noinline)) static struct Big indirect(struct Big (*f)(struct Big), struct Big x) { return f(x); }
long entry(int corrupt) {
 long value=7, destination=0;
 struct Big original={1,2,3,&value};
 struct Big result=indirect(change, original);
 if (original.a!=1 || original.b!=2 || result.a!=8 || result.b!=3 || result.p!=&value) return 1;
 struct Big r=recursive(original,3); if(r.a!=5 || original.a!=1) return 5;
 struct Big alias={10,20,30,0}; alias.p=&alias.a;
 struct Big ac=change(alias); if(ac.a!=20 || alias.a!=10 || ac.p!=&alias.a) return 6;
 Callback f=obtain();
 if (f!=callback || f(&value,5)!=&value || value!=12) return 2;
 if (copy_table[0]!=memcpy || copy(copy_table[0],&destination,&value)!=&destination || destination!=12) return 3;
 if (corrupt) { f((long *)((unsigned long)&value ^ (1ul<<55)),1); return 4; }
 return 0;
}
'''
ORACLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define TAG (0x825aULL<<48)
static struct { uintptr_t base; size_t n; } slots[4096];
static unsigned count;
uintptr_t encbound_stack_mint(void *p, size_t n) {
 assert(count<4096 && !((uintptr_t)p & (n-1))); memset(p,0,n);
 slots[count].base=(uintptr_t)p; slots[count++].n=n; return (uintptr_t)p|TAG;
}
uintptr_t encbound_require(uintptr_t p, size_t n, int kind) {
 assert(n && (kind==1 || kind==2));
 if (!(p>>48)) return p; /* only native fixture globals; no isolation claim */
 if ((p & (0xffffULL<<48)) != TAG) _Exit(77);
 uintptr_t raw=p & ((1ULL<<48)-1);
 for(unsigned i=0;i<count;i++) if(raw>=slots[i].base && raw-slots[i].base<slots[i].n && n<=slots[i].n-(raw-slots[i].base)) return raw;
 _Exit(77);
}
void *encbound_memcpy(void *d,const void *s,size_t n) {
 if(n) memcpy((void*)encbound_require((uintptr_t)d,n,2),(void*)encbound_require((uintptr_t)s,n,1),n);
 return d;
}
extern long entry(int);
int main(int argc,char **argv) { (void)argv; assert(entry(argc>1)==0); puts("compiler semantics PASS"); }
'''
for n, text in {'api.h':HEADER,'callee.c':CALLEE,'caller.c':CALLER,'oracle.c':ORACLE}.items(): (OUT/n).write_text(text)
(OUT/'admit').write_text('change\ncallback\nobtain\nrecursive\n')
rows=[]
for profile in ('RADIX_ONLY','MAC27'):
 for opt in ('-O0','-O2'):
  env=dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_CALLBACKS='1', ENCBOUND_AGGREGATE_ABI='1', ENCBOUND_CODEGEN_OPT=opt, ENCBOUND_ADMITTED=str(OUT/'admit'))
  objects=[]
  for unit in ('callee','caller'):
   obj=OUT/f'{unit}-{profile}{opt}.o'; objects.append(obj)
   run([ROOT/'tools/encbound-cc.sh',OUT/(unit+'.c'),obj,opt,'-fno-builtin','-fno-common'],env=env)
   ir=obj.with_suffix('.checked.ll').read_text()
   assert 'byval(' not in ir and 'sret(' not in ir
   assert '__encbound_abi_' in ir
  exe=OUT/f'test-{profile}{opt}'
  run(['clang-21',OUT/'oracle.c',*objects,'-o',exe]);run([exe])
  p=subprocess.run([exe,'corrupt'])
  assert p.returncode==77, p.returncode
  rows.append({'profile':profile,'optimization':opt,'semantics':'pass','corruption_exit':p.returncode})
# Valid LLVM modules that must be rejected by ENCBound itself.
negatives={
 'wrong_prototype':'declare i32 @memcpy(ptr, ptr, i64)\n@p = global ptr @memcpy',
 'helper_address':'declare i64 @encbound_require(i64,i64,i32)\n@p = global ptr @encbound_require',
 'unknown_address':'declare void @raw_sdk(ptr)\n@p = global ptr @raw_sdk',
 'format_address':'declare i32 @snprintf(ptr,i64,ptr,...)\n@p = global ptr @snprintf',
 'variadic_indirect':'define void @f(ptr %p) { call void (...) %p()\n ret void }',
 'aggregate_mismatch':'declare void @f(ptr byval(i64))\ndefine void @g(ptr %p) { call void @f(ptr %p)\n ret void }',
 'musttail':'define void @f(ptr byval(i64) %p) { musttail call void @f(ptr byval(i64) %p)\n ret void }',
 'external_aggregate':'declare void @unknown(ptr byval(i64))\ndefine void @f(ptr %p) { call void @unknown(ptr byval(i64) %p)\n ret void }',
}
for name, ir in negatives.items():
 path=OUT/(name+'.ll');path.write_text('target triple = "x86_64-pc-linux-gnu"\n'+ir+'\n')
 run(['opt-21','-passes=verify','-disable-output',path])
 p=subprocess.run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-encbound-callbacks','-encbound-aggregate-abi','-passes=encbound,encbound-verify,verify','-disable-output',str(path)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (OUT/(name+'.log')).write_text(p.stdout)
 assert p.returncode and 'ENCBound:' in p.stdout, name
 rows.append({'negative':name,'result':'rejected'})
# A separately compiled declaration/definition with differing original aggregate
# layout must not link, even though both normalize to opaque pointer arguments.
source=(OUT/'callee-MAC27-O0.input.ll').read_text()
assert '%struct.Big = type { i64, i64, i64, ptr }' in source
(OUT/'mismatch.ll').write_text(source.replace('%struct.Big = type { i64, i64, i64, ptr }','%struct.Big = type { i64, i64, i64, ptr, i64 }'))
run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-encbound-aggregate-abi','-passes=encbound,encbound-verify,verify','-S',OUT/'mismatch.ll','-o',OUT/'mismatch.checked.ll'])
run(['clang-21','-c',OUT/'mismatch.checked.ll','-o',OUT/'mismatch.o'])
p=subprocess.run(['clang-21',str(OUT/'oracle.c'),str(OUT/'caller-MAC27-O0.o'),str(OUT/'mismatch.o'),'-o',str(OUT/'must-not-link')],text=True,capture_output=True)
assert p.returncode and '__encbound_abi_' in p.stderr
rows.append({'negative':'cross-unit aggregate layout mismatch','result':'link rejected'})
# Corrupt the explicit copy length while keeping valid checked addresses.
import re
ir=(OUT/'callee-MAC27-O0.checked.ll').read_text()
mutated=re.sub(r'(call void @llvm.memcpy[^\n]*i64 )32(, i1 false)',r'\g<1>31\2',ir,count=1)
assert mutated!=ir
(OUT/'bad-copy.ll').write_text(mutated)
p=subprocess.run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes=encbound-verify,verify','-disable-output',str(OUT/'bad-copy.ll')],text=True,capture_output=True)
assert p.returncode and 'byval entry copy' in p.stderr
rows.append({'negative':'independent byval verifier copy length','result':'rejected'})
(OUT/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('INTEGRATION COMPILER PASS:', len(rows), 'rows')
