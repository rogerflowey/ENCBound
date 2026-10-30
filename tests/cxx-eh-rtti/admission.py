#!/usr/bin/env python3
"""EH input rejection and independently checked output mutation controls."""
import hashlib,json,os,re,resource,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];B=R/'build/integration/cxx-eh-rtti/admission';B.mkdir(parents=True,exist_ok=True)
S=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))
resource.setrlimit(resource.RLIMIT_CORE,(0,0));rows=[]
def run(name,command,good=False,env=None,diagnostic='ENCBound:'):
 p=subprocess.run(list(map(str,command)),env=env,capture_output=True,text=True,timeout=120);text=p.stdout+p.stderr
 (B/(name+'.log')).write_text(text)
 assert (p.returncode==0)==good and (good or diagnostic in text),(name,p.returncode,text[-5000:])
 rows.append(dict(case=name,result='pass',expected='accept' if good else 'reject',diagnostic=diagnostic if not good else None))
 return text
run('plugin',['make','-C',R/'pass'],good=True)
flags=['-x','c++','-std=c++17','-O0','-fexceptions','-frtti','-nostdinc','-nostdinc++','-fno-common','-fno-builtin',
       '-I'+str(R/'build/integration/cxx-eh-rtti/headers'),'-I'+str(S/'include/libcxx'),'-I'+str(S/'include/tlibc'),'-I'+str(S/'include')]
cases={
 'virtual-base':'#include <typeinfo>\nstruct B{};struct D:virtual B{};const char*f(){return typeid(D).name();}',
 'function-type':'#include <typeinfo>\nconst char*f(){return typeid(int(double)).name();}',
 'function-pointer-identity':'#include <typeinfo>\nconst char*f(){return typeid(int(*)(double)).name();}',
 'private-base':'#include <typeinfo>\nstruct B{};struct D:private B{};const char*f(){return typeid(D).name();}',
 'protected-base':'#include <typeinfo>\nstruct B{};struct D:protected B{};const char*f(){return typeid(D).name();}',
 'repeated-base':'#include <typeinfo>\nstruct B{};struct A:B{};struct C:B{};struct D:A,C{};const char*f(){return typeid(D).name();}',
 'member-pointer':'struct A{int n;};void f(){throw &A::n;}',
 'function-pointer':'void g(){};void f(){throw &g;}',
 'function-pointer-catch':'void f(){try{throw 1;}catch(void(*)()){}}',
 'exception-ptr':'extern "C" void *__cxa_current_primary_exception();void*f(){return __cxa_current_primary_exception();}',
 'forged-token':'extern "C" void *__cxa_begin_catch(void*);void*f(void*p){return __cxa_begin_catch(p);}',
 'personality-call':'extern "C" int __gxx_personality_v0(...);int f(){return __gxx_personality_v0();}',
 'raw-private-service':'extern "C" void encbound_eh_boundary_clean();void f(){encbound_eh_boundary_clean();}',
 'foreign-personality':'extern "C" void _Unwind_Resume(void*);void f(void*p){_Unwind_Resume(p);}',
 'application-tls':'thread_local int x;int f(){return ++x;}',
}
for name,source in cases.items():
 src=B/(name+'.cpp');src.write_text(source+'\n')
 run(name,[R/'tools/with-integration-defaults.sh','env','ENCBOUND_CXX_EH=1','ENCBOUND_PROFILE=MAC27',R/'tools/encbound-cc.sh',src,B/(name+'.o'),*flags],good=name in ('virtual-base','function-type','function-pointer-identity','private-base','protected-base','repeated-base'))
# Work from the actual separately compiled throw/catch output, not a parallel
# model of the transformation. LLVM structural validity is checked first.
source=R/'build/integration/cxx-eh-rtti/MAC27-0x40000000-O2-O2/app.checked.ll';original=source.read_text()
options=['-encbound-'+n+'=1' for n in ('callbacks','cxx-allocations','aggregate-abi','atomics','virtuals','variadics','protected-globals','cxx-lifecycle','vla','cxx-eh')]
command=['opt-21','-load-pass-plugin='+str(R/'build/pass/encbound_pass.so'),'-passes=encbound-verify,verify','-disable-output',*options]
run('unchanged-output',[*command,source],good=True)
# Find one actual private-token extraction from a landingpad.
match=re.search(r'^(  (%[\w.]+) = extractvalue \{ ptr, i32 \} %[^,\n]+, 0[^\n]*)\n',original,re.M);assert match
line,token=match.group(1),match.group(2)
mutations={
 'token-store':original.replace(line,line+'\n  store ptr '+token+', ptr @escape',1)+'\n@escape = global ptr null\n',
 'token-integer':original.replace(line,line+'\n  %escaped = ptrtoint ptr '+token+' to i64',1),
 'token-call':original.replace(line,line+'\n  call void @sink(ptr '+token+')',1)+'\ndeclare void @sink(ptr)\n',
 'wrong-personality':original.replace('personality ptr @encbound_eh_personality','personality ptr @foreign_personality')+'\ndeclare i32 @foreign_personality(...)\n',
 'forged-catch':re.sub(r'(@encbound_eh_begin_catch\(ptr )%[^)]+',r'\1null',original,count=1),
 'boundary-clean-omitted':original.replace('  call void @encbound_eh_boundary_clean()\n','',1),
 'boundary-termination-omitted':original.replace('  call void @encbound_cxx_fail()\n  unreachable\n}', '  unreachable\n}',1),
 'missing-mode':original.replace('@__encbound_cxx_eh_v1','@missing_mode'),
 'helper-address':original+'\n@leaked_service = constant ptr @encbound_eh_begin_catch\n',
 'helper-prototype':original.replace('declare ptr @encbound_eh_begin_catch(ptr)','declare ptr @encbound_eh_begin_catch(i64)',1),
 'raw-unwinder-call':original.replace(line,line+'\n  call void @_Unwind_Resume(ptr '+token+')',1)+'\ndeclare void @_Unwind_Resume(ptr)\n',
}
check=re.search(r'^(  %[\w.]+ = )call i64 @encbound_require\(i64 ([^,]+), i64 [^,]+, i32 [^)]+\)[^\n]*',original,re.M);assert check
mutations['omitted-memory-check']=original[:check.start()]+check.group(1)+'add i64 '+check.group(2)+', 0'+original[check.end():]
startup=re.search(r'(@llvm.global_ctors = [^\n]*ptr )(@__encbound_eh_callback_[^,]+)',original);assert startup
wrapper=startup.group(2);target=wrapper.replace('@__encbound_eh_callback_','@')
mutations['unprepared-startup']=original[:startup.start(2)]+target+original[startup.end(2):]
registration=re.search(r'(@encbound_cxx_atexit\(ptr )(@__encbound_eh_callback_[^,]+)',original);assert registration
wrapper=registration.group(2);target=wrapper.replace('@__encbound_eh_callback_','@')
mutations['unprepared-destructor']=original[:registration.start(2)]+target+original[registration.end(2):]
# Mutate a catch descriptor's ABI vtable pointer while preserving well-typed IR.
metadata=re.search(r'^(@__encbound_type__ZTI\w+ = .*?getelementptr inbounds?[^\n]*)',original,re.M)
if not metadata: metadata=re.search(r'^(@__encbound_type__ZTI\w+ = .*getelementptr[^\n]*)',original,re.M)
assert metadata
row=metadata.group(1)
mutations['metadata-layout']=original.replace(row,row.replace('i64 2)','i64 1)'),1)
for name,text in mutations.items():
 assert text!=original,name
 src=B/(name+'.ll');src.write_text(text)
 run(name+'-llvm',['opt-21','-passes=verify','-disable-output',src],good=True)
 run(name,[*command,src])
# Reused SDK const methods must remain private application definitions. This
# catches a missing const-mangling ownership rule even when the linker could
# otherwise bind the raw method name to SDK code.
sdk_ir=source.with_name('typeinfo.checked.ll').read_text()
method=re.search(r'@(__encbound_type__ZNK10__cxxabiv1\w+)\(',sdk_ir).group(1)
text=sdk_ir.replace(method,method.removeprefix('__encbound_type_'))
src=B/'raw-sdk-const-method.ll';src.write_text(text)
run('raw-sdk-const-method-llvm',['opt-21','-passes=verify','-disable-output',src],good=True)
run('raw-sdk-const-method',[*command,src])
# Keep the validated negative, aligned virtual-offset ABI shape after widening
# graph admission. The actual VLeft descriptor is defined in the other unit.
virtual_ir=source.with_name('other.checked.ll').read_text()
line=re.search(r'^@__encbound_type__ZTI5VLeft = .*$',virtual_ir,re.M).group(0)
offset=re.search(r'i64 (-\d+)',line).group(1)
text=virtual_ir.replace(line,line.replace('i64 '+offset,'i64 '+str(int(offset)+256),1),1)
src=B/'unaligned-virtual-offset.ll';src.write_text(text)
run('unaligned-virtual-offset-llvm',['opt-21','-passes=verify','-disable-output',src],good=True)
run('unaligned-virtual-offset',[*command,src])
# Wider graph admission retains exact ABI flags and descriptor-array extents.
for name,changed in {
 'unknown-base-flags':line.replace('i64 '+offset,'i64 '+str(int(offset)|4),1),
 'unknown-graph-flags':line.replace('i32 0, i32 1,','i32 4, i32 1,',1),
 'wrong-base-count':line.replace('i32 0, i32 1,','i32 0, i32 2,',1),
}.items():
 assert changed!=line,name
 src=B/(name+'.ll');src.write_text(virtual_ir.replace(line,changed,1))
 run(name+'-llvm',['opt-21','-passes=verify','-disable-output',src],good=True)
 run(name,[*command,src])
run('output-without-mode',[c for c in command if c!='-encbound-cxx-eh=1']+[source])
for option in ('-encbound-local-proofs=1','-encbound-check-reuse=loop','-encbound-fast-paths=inline'):
 src=B/'virtual-base.cpp'
 # Driver combinations must be rejected before instrumentation.
 key={'-encbound-local-proofs=1':'ENCBOUND_LOCAL_PROOFS=1','-encbound-check-reuse=loop':'ENCBOUND_CHECK_REUSE=loop','-encbound-fast-paths=inline':'ENCBOUND_FAST_PATHS=inline'}[option]
 run('combination-'+option.split('=')[0],[R/'tools/with-integration-defaults.sh','env','ENCBOUND_CXX_EH=1','ENCBOUND_PROFILE=MAC27',key,R/'tools/encbound-cc.sh',src,B/'combination.o',*flags])
(B/'results.json').write_text(json.dumps(dict(rows=rows,source_ir_sha256=hashlib.sha256(source.read_bytes()).hexdigest()),indent=2)+'\n')
print('CXX EH ADMISSION/OUTPUT CONTROLS PASS',len(rows))
