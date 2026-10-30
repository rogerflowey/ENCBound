#!/usr/bin/env python3
"""Native real checked runtime/ABI adaptation on an actual reserved stack."""
import hashlib,json,os,resource,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2];H=Path(__file__).resolve().parent
B=R/'build/integration/cxx-eh-rtti/native';B.mkdir(parents=True,exist_ok=True)
S=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))
P=Path(str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx'))))
resource.setrlimit(resource.RLIMIT_CORE,(0,0));rows=[]
def run(name,cmd,env=None):
 p=subprocess.run(list(map(str,cmd)),env=env,capture_output=True,text=True,timeout=120)
 (B/(name+'.log')).write_text(p.stdout+p.stderr);assert p.returncode==0,(name,p.returncode,p.stdout,p.stderr)
 return p
run('plugin',['make','-C',R/'pass'])
run('headers',['python3',R/'runtime/cxx_eh/prepare.py','--out',B/'abi'])
run('cxx-headers',['python3',R/'tools/prepare_cxx_headers.py','--sdk',S,'--out',B/'headers'])
# Use only the pinned guard member. Native unwind calls resolve to system libgcc;
# real Intel SDK unwind-table discovery is independently exercised by SIM.
archive=S/'lib64/libsgx_tcxx.a';assert hashlib.sha256(archive.read_bytes()).hexdigest()=='50731a201df955b9fab2f4b6292c5c9004bcfc089fa7af4ad956a97bb8fa1a21'
(B/'guard.o').write_bytes(subprocess.check_output(['ar','p',str(archive),'guard.o']))
(B/'tcxx_version.o').write_bytes(subprocess.check_output(['ar','p',str(archive),'tcxx_version.o']))
entries=B/'entries.txt';entries.write_text('exercise\n')
for profile in ('RADIX_ONLY','MAC27'):
 for fe,cg,base in [('O0','O0','0x40000000'),('O2','O2','0x140000000')]:
  key=f'{profile}-{fe}-{cg}';out=B/key;out.mkdir(exist_ok=True)
  flags=['-g','-fpie','-ffunction-sections','-fdata-sections','-'+fe,'-nostdinc','-nostdinc++','-std=c++17','-fexceptions','-frtti',
         '-fno-common','-fno-builtin','-I'+str(B/'headers'),'-I'+str(S/'include/libcxx'),'-I'+str(S/'include/tlibc'),'-I'+str(S/'include')]
  sources=[H/'app.cpp',H/'other.cpp',R/'apps/cxx-abi/typeinfo.cpp'];definitions=set()
  for src in sources:
   obj=out/(src.stem+'.front.o');run(key+'-'+src.stem+'-front',['clang++-21',*flags,'-c',src,'-o',obj])
   definitions|={l.split()[-1] for l in subprocess.check_output(['nm','--defined-only',str(obj)],text=True).splitlines() if l.strip()}
  admitted=out/'admitted.txt';admitted.write_text('\n'.join(sorted(definitions))+'\n')
  env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CXX_EH='1',ENCBOUND_CXX_EH_ENTRIES=str(entries))
  objects=[]
  for src in sources:
   obj=out/(src.stem+'.o');run(key+'-'+src.stem,[R/'tools/with-integration-defaults.sh','env','ENCBOUND_CODEGEN_OPT=-'+cg,R/'tools/encbound-cc.sh',src,obj,'-x','c++',*flags],env)
   placed=out/(src.stem+'.placed.o');run(key+'-'+src.stem+'-place',['python3',R/'tools/mark_app_globals.py',obj,placed])
   # Native-only scheduling fixture: retain actual compiler callback records,
   # then execute them on the reserved application stack instead of libc's
   # unclassified startup stack. Application bodies/checks are unchanged.
   native=out/(src.stem+'.native.o');run(key+'-'+src.stem+'-init-records',['objcopy','--rename-section','.init_array=encbound_native_init',placed,native]);objects.append(native)
  trusted=[];cflags=['-O2','-g','-fpie',*['-I'+str(R/d) for d in ('include','runtime')]]
  if profile=='MAC27':cflags+=['-DENCBOUND_MAC27']
  for n in ('check_core','allocations','allocator','adapters','cxx_lifecycle','cxx_allocations','cxx_services'):
   obj=out/(n+'.o');run(key+'-'+n,['clang-21',*cflags,'-c',R/f'runtime/{n}.c','-o',obj]);trusted.append(obj)
  obj=out/'eh.o';run(key+'-eh',['clang++-21',*cflags,'-std=c++17','-fno-exceptions','-fno-rtti','-I'+str(B/'abi'),'-I'+str(P/'common/inc/internal'),'-c',R/'runtime/cxx_eh/runtime.cpp','-o',obj]);trusted.append(obj)
  harness=out/'native.o';run(key+'-harness',['clang-21',*cflags,'-c',H/'native.c','-o',harness])
  exe=out/'native'
  run(key+'-link',['clang-21',harness,*objects,*trusted,B/'guard.o',B/'tcxx_version.o','-lgcc_s','-lm','-Wl,--wrap=calloc,--wrap=free,--wrap=abort,--wrap=__cxa_atexit','-pie','-Wl,-Ttext-segment='+base,'-Wl,-T,'+str(R/'sdk/enclave_sections.lds'),'-o',exe])
  p=run(key+'-run',[exe]);print(key,p.stdout.strip(),flush=True)
  rows.append(dict(mode='native real runtime / native libgcc unwinder / pinned SDK guards',profile=profile,frontend=fe,codegen=cg,base=base,output=p.stdout.strip(),exe_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),result='pass'))
(B/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
