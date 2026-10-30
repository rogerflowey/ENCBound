#!/usr/bin/env python3
"""Build a private, instrumented Intel libc++ archive, with a closed inventory."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];OUT=Path(os.environ.get('ENCBOUND_LIBCXX_PREPARED',ROOT/'build/libcxx')).resolve()
SDK=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))).resolve()
p=argparse.ArgumentParser();p.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'],required=True)
p.add_argument('--out-dir',type=Path)
p.add_argument('--frontend',choices=['O0','O2'],default='O2')
p.add_argument('--caller',type=Path,action='append')
p.add_argument('--caller-flag',action='append',default=[])
a=p.parse_args()
eh=os.environ.get('ENCBOUND_CXX_EH')=='1'
subprocess.run(['python3',ROOT/'apps/libcxx/verify.py'],check=True)
source=json.loads((OUT/'sources.json').read_text());out=(a.out_dir or OUT/a.profile).resolve();out.mkdir(parents=True,exist_ok=True)
flags=['-std=c++17','-fno-exceptions','-fno-rtti','-fno-threadsafe-statics','-fno-common','-fno-builtin','-nostdinc','-nostdinc++','-fvisibility=hidden','-fpie','-ffunction-sections','-fdata-sections','-fstack-protector-strong','-I'+str(OUT/'headers'),'-I'+str(SDK/'include/libcxx'),'-I'+str(SDK/'include/tlibc'),'-I'+str(SDK/'include'),'-O2']
flags[-1]='-'+a.frontend
app_errno=os.environ.get('ENCBOUND_APP_ERRNO')=='1'
if app_errno:
 flags=['-I'+str(ROOT/'include/encbound_app_libc'),'-I'+str(ROOT/'include')]+flags
for f in ['memchr','wmemcpy','wmemmove','wmemset','wmemchr','wmemcmp','wcslen']:flags.append(f'-D{f}=app_libcxx_{f}')
if os.environ.get('ENCBOUND_CXX_LIFECYCLE')=='1':flags.append('-DENCBOUND_TEST_CXX_LIFECYCLE=1')
units=source['units']
if eh:
 flags=[f for f in flags if f not in ('-fno-exceptions','-fno-rtti','-fno-threadsafe-statics')]+['-fexceptions','-frtti']
 # Bounded EH library configuration: these bodies and throw helpers are rebuilt
 # with callers. Threading/locale/I/O/retained exception handles stay excluded.
 units=['algorithm','atomic','functional','hash','utility','vector','string',
        'stdexcept','optional','any','variant','memory_eh']
inputs=[OUT/'src'/f'{n}.cpp' for n in units]+[ROOT/'apps/libcxx/wide_memory.cpp']
if eh and a.profile!='BASELINE':inputs.append(ROOT/'apps/cxx-abi/typeinfo.cpp')
# Include all application TUs in the same exact declaration inventory, if supplied.
app_sources=a.caller or []
if not app_sources: p.error('supply --caller for every selected application translation unit')
all_inputs=inputs+app_sources
front=[];definitions=set()
for src in all_inputs:
 ir=out/(src.stem+'.frontend.ll');log=out/(src.stem+'.frontend.log')
 cmd=['clang++-21',*flags,*(a.caller_flag if src in app_sources else []),'-S','-emit-llvm',str(src),'-o',str(ir)]
 run=subprocess.run(cmd,capture_output=True,text=True);log.write_text(run.stderr)
 if run.returncode:raise SystemExit(f'frontend failed: {src}: {run.stderr[:1500]}')
 text=ir.read_text();definitions.update(re.findall(r'^define .*?@([^ (]+)\(',text,re.M))
 definitions.update(re.findall(r'^@([^ ]+) = .*?alias ',text,re.M))
 front.append(dict(source=str(src),ir=str(ir)))
if app_errno:
 # These are application definitions supplied once by libc/errno.c in the
 # final closure (the selected formatter also builds that provider). They
 # remain ordinary admitted application calls, never raw SDK services.
 provider=out/'errno-provider.frontend.ll'
 subprocess.run(['clang-21','-O2','-I'+str(ROOT/'include'),'-S','-emit-llvm',
                 ROOT/'libc/errno.c','-o',provider],check=True)
 definitions.update(re.findall(r'^define .*?@([^ (]+)\(',provider.read_text(),re.M))
admitted=out/'admitted.txt';admitted.write_text('\n'.join(sorted(definitions))+'\n')
env=dict(os.environ,ENCBOUND_PROFILE=a.profile,ENCBOUND_CALLBACKS='1',ENCBOUND_AGGREGATE_ABI='1',ENCBOUND_CXX_ALLOCATIONS='1',ENCBOUND_ATOMICS='1',ENCBOUND_VIRTUALS='1',ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CODEGEN_OPT=os.environ.get('ENCBOUND_CODEGEN_OPT','-O2'),ENCBOUND_WRITABLE_GLOBALS='1')
objects=[]
for src in inputs:
 obj=out/(src.stem+'.o');cmd=[ROOT/'tools/encbound-cc.sh',src,obj,*flags]
 run=subprocess.run(cmd,capture_output=True,text=True,env=env);(out/(src.stem+'.build.log')).write_text(run.stdout+run.stderr)
 if run.returncode:raise SystemExit(f'instrumentation failed: {src}: {run.stderr[:1800]}')
 subprocess.run([ROOT/'tools/mark_appdata_sections.sh',obj,str(obj)+'.placed'],check=True,env=env,stdout=subprocess.DEVNULL)
 Path(str(obj)+'.placed').replace(obj);Path(str(obj)+'.placed.ownership.json').replace(str(obj)+'.ownership.json')
 objects.append(obj)
archive=out/'libencbound_cxx.a';archive.unlink(missing_ok=True)
subprocess.run(['ar','rcs',archive,*objects],check=True)
record={'profile':a.profile,'cxx_eh':eh,'selected_units':units,'flags':flags,'source_inventory':source,'objects':[str(o) for o in objects],'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'frontend':front,'admitted':str(admitted),'callers':{str(s.resolve()):hashlib.sha256(s.read_bytes()).hexdigest() for s in app_sources},'caller_flags':a.caller_flag}
(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
print('LIBCXX ARCHIVE BUILT',a.profile,len(objects))
