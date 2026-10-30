#!/usr/bin/env python3
"""Atomic check-before-access, ordering preservation and alias admission gates."""
from pathlib import Path
import json,re,resource,subprocess
R=Path(__file__).resolve().parents[2];B=R/'build/pass/atomic-virtual';B.mkdir(parents=True,exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
header='target triple = "x86_64-pc-linux-gnu"\n'
rows=[]
def run(name,body,good=True,verify=False,enabled=True):
 src=B/(name+'.ll');dst=B/(name+'.checked.ll');src.write_text(header+body)
 subprocess.run(['opt-21','-passes=verify','-disable-output',src],check=True)
 cmd=['opt-21','-load-pass-plugin='+str(R/'build/pass/encbound_pass.so'),'-passes='+('encbound-verify,verify' if verify else 'encbound,encbound-verify,verify'),'-S',src,'-o',dst]
 if enabled:cmd+=['-encbound-atomics','-encbound-virtuals','-encbound-callbacks','-encbound-aggregate-abi']
 p=subprocess.run(cmd,capture_output=True,text=True);(B/(name+'.log')).write_text(p.stderr)
 assert (p.returncode==0)==good,(name,p.stderr)
 if not good:assert 'ENCBound:' in p.stderr,(name,p.stderr)
 rows.append(dict(case=name,expected='accept' if good else 'reject',result='pass'))
 return dst.read_text() if good else ''
for bits in (8,16,32,64):
 t=f'i{bits}';n=bits//8
 body=f'''define {t} @load{bits}(ptr %p) {{
 %v = load atomic volatile {t}, ptr %p syncscope("singlethread") acquire, align {n}
 ret {t} %v
}}
define void @store{bits}(ptr %p, {t} %v) {{
 store atomic volatile {t} %v, ptr %p release, align {n}
 ret void
}}
define {t} @add{bits}(ptr %p, {t} %v) {{
 %old = atomicrmw volatile add ptr %p, {t} %v acq_rel, align {n}
 ret {t} %old
}}
define {t} @cas{bits}(ptr %p, {t} %old, {t} %new) {{
 %r = cmpxchg ptr %p, {t} %old, {t} %new acq_rel acquire, align {n}
 %v = extractvalue {{ {t}, i1 }} %r, 0
 ret {t} %v
}}
define void @fence{bits}() {{
 fence seq_cst
 ret void
}}
'''
 checked=run('positive'+str(bits),body)
 for kind in (1,2,3):assert f'i64 {n}, i32 {kind})' in checked
 for token in ['load atomic volatile','store atomic volatile','atomicrmw volatile add','cmpxchg','acq_rel acquire','syncscope("singlethread") acquire','fence seq_cst']:assert token in checked,token
run('default-reject','define void @f() { fence seq_cst\n ret void }',False,enabled=False)
for name,inst in [('wide','%v = atomicrmw add ptr %p, i128 1 seq_cst, align 16'),('unaligned','%v = atomicrmw add ptr %p, i64 1 seq_cst, align 4'),('pointer','%v = load atomic ptr, ptr %p acquire, align 8'),('float','%v = atomicrmw fadd ptr %p, float 1.0 seq_cst, align 4')]:
 run(name,'define void @f(ptr %p) {\n'+inst+'\nret void\n}',False)
req='declare i64 @encbound_require(i64, i64, i32)\n'
for op in ['%v = atomicrmw add ptr %q, i64 1 seq_cst, align 8','%v = cmpxchg ptr %q, i64 1, i64 2 seq_cst acquire, align 8']:
 for name,width,kind,escape in [('good',8,3,False),('short',4,3,False),('read',8,1,False),('write',8,2,False),('escape',8,3,True)]:
  body=req+'define i64 @f(i64 %cap) {\n'+f'%raw = call i64 @encbound_require(i64 %cap, i64 {width}, i32 {kind})\n%q = inttoptr i64 %raw to ptr\n'+op+'\nret i64 '+('%raw' if escape else '0')+'\n}'
  run(('rmw-' if 'atomicrmw' in op else 'cas-')+name,body,name=='good',verify=True)
 for name in ['raw']:
  run(('rmw-' if 'atomicrmw' in op else 'cas-')+name,'define void @f(ptr %q) {\n'+op+'\nret void\n}',False,verify=True)
run('alias', '@alias = internal alias void (), ptr @f\ndefine internal void @f() {ret void}\ndefine void @g() { call void @alias()\nret void }')
run('offset-alias', '@alias = internal alias void (), ptr getelementptr (i8, ptr @f, i64 1)\ndefine internal void @f() {ret void}',False)
run('data-alias','@x = global i64 0\n@alias = internal alias i64, ptr @x',False)
run('interposable-alias','@alias = weak alias void (), ptr @f\ndefine void @f() {ret void}',False)
run('aggregate-alias','@alias = internal alias void (ptr), ptr @f\ndefine internal void @f(ptr sret(i64) %p) {ret void}',False)
run('surviving-assume','declare void @llvm.assume(i1)\ndefine void @f() {call void @llvm.assume(i1 true)\nret void}',False,verify=True)
scope='declare void @llvm.experimental.noalias.scope.decl(metadata)\ndefine void @f() {call void @llvm.experimental.noalias.scope.decl(metadata !2)\nret void}\n!0 = distinct !{!0, !1, !"scope"}\n!1 = distinct !{!1, !"domain"}\n!2 = !{!0}\n'
assert 'call void @llvm.experimental.noalias.scope.decl' not in run('remove-noalias',scope)
run('surviving-noalias',scope,False,verify=True)
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('ATOMIC/VIRTUAL ADMISSION AND VERIFIER PASS',len(rows),'cases')
