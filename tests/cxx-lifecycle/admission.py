#!/usr/bin/env python3
"""Fail-closed lifecycle input/output admission and final-link controls."""
import json,resource,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];B=ROOT/'build/integration/cxx-lifecycle/admission'
B.mkdir(parents=True,exist_ok=True);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
PLUGIN=ROOT/'build/pass/encbound_pass.so';rows=[]
BASE='target triple = "x86_64-pc-linux-gnu"\ntarget datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"\n'
BODY='define internal void @init() { ret void }\n'
LIST='@llvm.global_ctors = appending global [1 x {i32,ptr,ptr}] [{i32,ptr,ptr} {i32 65535,ptr @init,ptr null}]\n'
flags=['-encbound-protected-globals=1','-encbound-cxx-lifecycle=1','-encbound-callbacks=1','-encbound-atomics=1']
cases={
 'disabled':(BODY+LIST,'enable lifecycle',['-encbound-cxx-lifecycle=0']),
 'globals-disabled':(BODY+LIST,'enable lifecycle',['-encbound-protected-globals=0']),
 'callbacks-disabled':(BODY+LIST,'requires protected globals and callbacks',['-encbound-callbacks=0']),
 'external-constructor':(LIST+'declare void @init()\n','startup function',[]),
 'wrong-constructor-abi':(LIST+'define void @init(ptr %p){ret void}\n','startup function',[]),
 'unknown-association':(BODY+LIST.replace('ptr null','ptr @data')+'@data = global i32 0\n','startup association',[]),
 'priority-type':(BODY+LIST.replace('i32','i64'),'wrong type for intrinsic global variable',[]),
 'table-load':(BODY+LIST+'define ptr @read(){ret ptr @llvm.global_ctors}\n','invalid uses of intrinsic global variable',[]),
 'registration-token':('declare i32 @__cxa_atexit(ptr,ptr,ptr)\ndefine void @d(ptr %p){ret void}\ndefine i32 @f(ptr %p){%r=call i32 @__cxa_atexit(ptr @d,ptr %p,ptr null)\nret i32 %r}\n','registration/DSO',[]),
 'registration-callback':('@__dso_handle=external global i8\ndeclare i32 @__cxa_atexit(ptr,ptr,ptr)\ndefine i32 @f(ptr %p,ptr %fn){%r=call i32 @__cxa_atexit(ptr %fn,ptr %p,ptr @__dso_handle)\nret i32 %r}\n','callback ABI',[]),
 'dso-load':('@__dso_handle=external global ptr\ndefine ptr @f(){%p=load ptr,ptr @__dso_handle\nret ptr %p}\n','DSO handle access',[]),
 'dso-definition':('@__dso_handle=global ptr null\n','DSO handle definition',[]),
 'weak-storage':('@x=weak global i64 0\n','linkage/section',[]),
 'non-odr-comdat':('$x=comdat any\n@x=weak global i64 0,comdat($x)\n','linkage/section',[]),
 'wrong-comdat-selection':('$x=comdat largest\n@x=weak_odr global i64 0,comdat($x)\n','linkage/section',[]),
 'custom-startup-storage':('@x=global i64 0,section ".init_array"\n','linkage/section',[]),
 'raw-guard-abi':('declare i32 @__cxa_guard_acquire(i64)\ndefine i32 @f(){%r=call i32 @__cxa_guard_acquire(i64 0)\nret i32 %r}\n','service ABI',[]),
 'tls':('@x=thread_local global i64 0\n','TLS',[]),
 'privileged-adapter':('declare i32 @encbound_cxx_atexit(ptr,ptr)\ndefine i32 @f(){%r=call i32 @encbound_cxx_atexit(ptr null,ptr null)\nret i32 %r}\n','privileged',[]),
}
for name,(source,want,extra) in cases.items():
    src=B/(name+'.ll');src.write_text(BASE+source)
    cmd=['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes=encbound,encbound-verify',*flags,*extra,'-disable-output',src]
    p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True)
    (B/(name+'.log')).write_text(p.stdout+p.stderr)
    assert p.returncode and want in p.stderr,(name,want,p.stderr)
    rows.append(dict(case=name,result='pass',diagnostic=want))
# The independent output verifier must also reject malformed startup metadata.
src=B/'bad-output.ll';src.write_text(BASE+LIST+'declare void @init()\n')
p=subprocess.run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes=encbound-verify',*flags,
                  '-disable-output',str(src)],capture_output=True,text=True)
assert p.returncode and 'startup function' in p.stderr,p.stderr
rows.append(dict(case='independent-startup-output-verifier',result='pass'))
# No-EH lifecycle callbacks are ordinary owned void(void*) functions. The EH
# verifier must not require an exception wrapper in this established mode.
source=BASE+'''@__dso_handle = external global i8
declare i32 @__cxa_atexit(ptr, ptr, ptr)
define void @destroy(ptr %p) { ret void }
define i32 @register(ptr %p) {
  %r = call i32 @__cxa_atexit(ptr @destroy, ptr %p, ptr @__dso_handle)
  ret i32 %r
}
'''
src=B/'ordinary-registration.ll';src.write_text(source)
out=B/'ordinary-registration.checked.ll'
cmd=['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes=encbound,encbound-verify',*flags,'-S',str(src),'-o',str(out)]
p=subprocess.run(cmd,capture_output=True,text=True)
assert p.returncode==0,p.stderr
text=out.read_text();assert 'call i32 @encbound_cxx_atexit(ptr @destroy, ptr %p)' in text
rows.append(dict(case='ordinary-noeh-registration',result='pass'))
for name,mutant in {
    'unknown-destructor':text.replace('ptr @destroy, ptr %p','ptr @unknown, ptr %p')+'\ndeclare void @unknown(ptr)\n',
    'runtime-destructor':text.replace('ptr @destroy, ptr %p','ptr %p, ptr %p'),
    'wrong-destructor-abi':text.replace('ptr @destroy, ptr %p','ptr @wrong, ptr %p')+'\ndefine void @wrong() { ret void }\n',
}.items():
    src=B/(name+'.ll');src.write_text(mutant)
    p=subprocess.run(['opt-21','-load-pass-plugin='+str(PLUGIN),'-passes=encbound-verify',*flags,
                      '-disable-output',str(src)],capture_output=True,text=True)
    (B/(name+'.log')).write_text(p.stdout+p.stderr)
    assert p.returncode and 'destructor registration ABI/ownership' in p.stderr,(name,p.stderr)
    rows.append(dict(case=name,result='pass'))
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX LIFECYCLE ADMISSION PASS',len(rows),'controls')
