#!/usr/bin/env python3
"""Valid LLVM input counterexamples and independent output mutations."""
import json,os,re,resource,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];H=Path(__file__).resolve().parent
B=R/'build/integration/vla/admission';B.mkdir(parents=True,exist_ok=True)
P=R/'build/pass/encbound_pass.so';resource.setrlimit(resource.RLIMIT_CORE,(0,0))
rows=[];commands=[]
def run(name,cmd,env=None,good=True):
 p=subprocess.run(list(map(str,cmd)),text=True,capture_output=True,env=env,timeout=60)
 (B/(name+'.log')).write_text(p.stdout+p.stderr)
 commands.append(dict(command=list(map(str,cmd)),returncode=p.returncode,log=name+'.log'))
 assert (p.returncode==0)==good,(name,p.stdout,p.stderr)
 return p
def reject(name,body,verify=False):
 src=B/(name+'.ll');src.write_text('target triple = "x86_64-pc-linux-gnu"\n'+body+'\n')
 run(name+'-valid-input',['opt-21','-passes=verify','-disable-output',src])
 p=run(name,['opt-21','-load-pass-plugin='+str(P),'-encbound-vla',
    '-passes=encbound-verify' if verify else '-passes=encbound,encbound-verify',
    '-disable-output',src],good=False)
 assert 'ENCBound:' in p.stderr,(name,p.stderr)
 rows.append(dict(case=name,kind='verifier mutation' if verify else 'input admission',result='rejected'))
save='declare ptr @llvm.stacksave.p0()\ndeclare void @llvm.stackrestore.p0(ptr)\n'
cases={
 'return-save':save+'define ptr @f(){ %s=call ptr @llvm.stacksave.p0()\nret ptr %s }',
 'argument-restore':save+'define void @f(ptr %p){ call void @llvm.stackrestore.p0(ptr %p)\nret void }',
 'loaded-restore':save+'define void @f(ptr %p){ %v=load ptr,ptr %p\ncall void @llvm.stackrestore.p0(ptr %v)\nret void }',
 'stored-save':save+'define void @f(ptr %p){ %s=call ptr @llvm.stacksave.p0()\nstore ptr %s,ptr %p\nret void }',
 'overwritten-cell':save+'''define void @f(ptr %p){
 %cell=alloca ptr
 %s=call ptr @llvm.stacksave.p0()
 store ptr %s,ptr %cell
 store ptr %p,ptr %cell
 %v=load ptr,ptr %cell
 call void @llvm.stackrestore.p0(ptr %v)
 ret void }''',
 'mixed-phi':save+'''define void @f(ptr %p,i1 %b){
 %s=call ptr @llvm.stacksave.p0()
 br i1 %b,label %a,label %c
a: br label %join
c: br label %join
join: %v=phi ptr [%s,%a],[%p,%c]
 call void @llvm.stackrestore.p0(ptr %v)
 ret void }''',
 'save-cycle':save+'''define void @f(i1 %b){
 %s=call ptr @llvm.stacksave.p0()
 br label %loop
loop: %v=phi ptr [%s,%0],[%v,%loop]
 call void @llvm.stackrestore.p0(ptr %v)
 br i1 %b,label %loop,label %end
end: ret void }''',
 'direct-helper':'declare i64 @encbound_stack_prepare(ptr,i64,i64,i64)\ndefine i64 @f(ptr %p){ %s=call i64 @encbound_stack_prepare(ptr %p,i64 1,i64 1,i64 16)\nret i64 %s }',
 'wide-count':'define ptr @f(i128 %n){ %a=alloca i8,i128 %n\nret ptr %a }',
 'variable-size-shift':'define ptr @f(i64 %n,i64 %s){ %c=shl i64 %n,%s\n%a=alloca i8,i64 %c\nret ptr %a }',
 'sizing-version':'define ptr @f(i64 %n){ %a=alloca i8,i64 %n\nret ptr %a }\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"encbound.vla.sizing", i32 99}',
}
for n,b in cases.items():reject(n,b)
src=B/'valid.c';src.write_text('extern void observe(void*);void f(unsigned long n){char a[n];observe(a);}\n')
admit=B/'admitted.txt';admit.write_text('observe\n')
env=dict(os.environ,ENCBOUND_PROFILE='MAC27',ENCBOUND_VLA='1',ENCBOUND_ADMITTED=str(admit))
obj=B/'valid.o';run('valid',['bash',R/'tools/encbound-cc.sh',src,obj,'-O2'],env)
ir=obj.with_suffix('.checked.ll').read_text()
def mutation(name,old,new):
 assert old in ir,(name,old)
 reject(name,ir.replace(old,new,1),True)
mutation('reserve-too-short','shl i64 %encbound.vla.size, 1','shl i64 %encbound.vla.size, 0')
mutation('reserve-too-long','shl i64 %encbound.vla.size, 1','shl i64 %encbound.vla.size, 2')
mutation('fake-sp','ptr %encbound.vla.sp,','ptr null,')
mutation('wrong-mint-size','ptr %encbound.vla.storage, i64 %encbound.vla.size','ptr %encbound.vla.storage, i64 16')
mutation('raw-reservation-escape','%encbound.vla.object =','store ptr %encbound.vla.storage,ptr null\n %encbound.vla.object =')
mutation('raw-token-escape','%encbound.vla.object =','store ptr %encbound.vla.sp,ptr null\n %encbound.vla.object =')
mutation('weak-alignment','i64 %encbound.vla.reserve, align 16','i64 %encbound.vla.reserve, align 8')
mutation('preflight-convention','call i64 @encbound_stack_prepare','call fastcc i64 @encbound_stack_prepare')
mutation('restore-from-object','ret void','call void @llvm.stackrestore.p0(ptr %encbound.vla.object)\n ret void') if '@llvm.stackrestore.p0' in ir else None
env['ENCBOUND_VLA']='0';bad=B/'off.o';bad.unlink(missing_ok=True)
p=run('default-off',[R/'tools/encbound-cc.sh',src,bad,'-O2'],env,False)
assert 'ENCBound:' in p.stderr and not bad.exists()
rows.append(dict(case='default-off',result='rejected without publishing object'))
env['ENCBOUND_VLA']='1';bad=B/'missing-sizing.o';bad.unlink(missing_ok=True)
p=run('missing-sizing',[R/'tools/encbound-cc.sh',src,bad,'-O2','-Xclang','-disable-llvm-passes'],env,False)
assert 'VLA sizing pass did not run' in p.stderr and not bad.exists()
rows.append(dict(case='missing-frontend-sizing',result='rejected without publishing object'))
# Token cycles and fake restores must also fail the standalone output verifier.
for n in ('argument-restore','mixed-phi','save-cycle'):reject('verify-'+n,cases[n],True)
(B/'results.json').write_text(json.dumps(dict(rows=rows,commands=commands),indent=2)+'\n')
print('VLA ADMISSION/VERIFIER PASS',len(rows))
