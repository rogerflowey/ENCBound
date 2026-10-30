#!/usr/bin/env python3
"""Build/run the original multi-person first-match analyzer and key manager."""
import argparse,hashlib,json,os,re,resource,shlex,subprocess,sys
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1]
S=Path(os.environ.get('SGX_SDK',R/'deps/sgxsdk'))
P=Path(os.environ.get('PINNED_SRC',R/'deps/intel-sgx'))
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'],default='MAC27')
ap.add_argument('--out',type=Path,default=R/'build/yeez/full-integration')
ap.add_argument('--compile-only',action='store_true')
options=ap.parse_args();B=options.out.resolve();assert B.is_relative_to(R/'build');B.mkdir(parents=True,exist_ok=True)
profile=options.profile;O=B/profile;O.mkdir(exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
source=R/'build/paper-sources/yeez'
source_specs=json.loads((R/'config/paper-sources.json').read_text())
for name in ('yeez','fflib'):
 item=source_specs[name]
 base=source if name=='yeez' else source/'vendor/fflib'
 for path,h in item['files'].items():assert hashlib.sha256((base/path).read_bytes()).hexdigest()==h,path
sys.path.insert(0,str(R/'tools'))
from audit_app_globals import audit
from check_early_bootstrap import audit as bootstrap_audit
from check_sdk_pins import SDK_BINARIES
commands=[]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(name,cmd,env=None):
 cmd=list(map(str,cmd));p=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=300)
 log=O/(name+'.log');log.write_text(p.stdout+p.stderr)
 commands.append(dict(label=name,command=cmd,returncode=p.returncode,log=str(log),log_sha256=sha(log)))
 print(profile,name,p.returncode,flush=True)
 if p.returncode:raise RuntimeError(log.read_text()[-7000:])
 return p
run('pass',['make','-C',R/'pass']);run('generator',['make','-C',R/'tools/edger8r'])
run('pins',['python3',R/'tools/check_sdk_pins.py','--sdk',S,'--pinned',P])
prepared=O/'libcxx-prepared';env={k:v for k,v in os.environ.items() if not k.startswith('ENCBOUND_')}
env.update(ENCBOUND_LIBCXX_PREPARED=str(prepared),SGX_SDK=str(S),PINNED_SRC=str(P),ENCBOUND_CXX_EH='1',
    ENCBOUND_PROFILE=profile,ENCBOUND_PLUGIN=str(R/'build/pass/encbound_pass.so'))
run('prepare-cxx',['python3',R/'apps/libcxx/prepare.py'],env)
run('prepare-eh',['python3',R/'runtime/cxx_eh/prepare.py','--out',O/'eh-headers'])
policy=json.loads((R/'apps/libc-format/boundary-interface.json').read_text());policy['records']={}
interface=O/'interface.json';interface.write_text(json.dumps(policy,indent=2)+'\n')
images={}
for kind,stem,edl,entry in [
 ('analyzer','eparser',source/'include/ypc/edl/eparser.edl',source/'example/multi_personlist/first_match/enclave/eparser.cpp'),
 ('keymgr','ekeymgr',source/'include/ypc/keymgr/default/enclave/ekeymgr.edl',source/'ypc/keymgr/default/enclave/ekeymgr.cpp')]:
 out=O/kind;out.mkdir(exist_ok=True);g=out/'generated';shim=out/'headers';shim.mkdir(exist_ok=True)
 cflags=['-m64','-O2','-g','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections',
  '-fstack-protector-strong','-fno-common','-fno-builtin','-fno-vectorize','-fno-slp-vectorize','-nostdinc',
  *['-I'+str(p) for p in (H,shim,g,R/'include',R/'runtime',R/'sdk',S/'include/tlibc',S/'include',source/'include')]]
 generator=['python3',R/'tools/modified_bridge.py','--cxx-eh','--edl',edl,'--interface',interface,
  '--generator',R/'build/edger8r/sgx_edger8r','--profile',profile,'--out-dir',g]
 for p in (S/'include',source/'include/ypc/edl',source/'include/ypc/edl/util',source/'include/ypc/stbox'):
  generator+=['--search-path',p]
 generator+=['--cflag='+f for f in cflags if f not in ('-fno-vectorize','-fno-slp-vectorize')]
 run(kind+'-generate',generator)
 for header in ('stbox_t.h','ecc_t.h'):(shim/header).write_text('#include "'+stem+'_t.h"\n')
 flags=[*cflags,'-std=c++17','-fexceptions','-frtti','-nostdinc++','-Wno-implicit-exception-spec-mismatch',
  '-Wno-extra-tokens','-fdelayed-template-parsing','-DYPC_ENABLE_SGX','-DYPC_SGX','-I'+str(prepared/'headers'),'-I'+str(S/'include/libcxx'),
  '-I'+str(source/'vendor/fflib/include'),'-include',str(g/(stem+'_t.h')),'-include',str(H/'full_services.h')]
 # Private libc++ headers precede SDK/system alternatives.
 flags.insert(0,'-I'+str(prepared/'headers'))
 flags+=['-D'+n+'=app_libcxx_'+n for n in ('memchr','wmemcpy','wmemmove','wmemset','wmemchr','wmemcmp','wcslen')]
 inventory=json.loads((H/'source-inputs.json').read_text())
 units={name:(source if item['root']=='source' else R)/item['path'] for name,item in inventory['units'].items()}
 for name,item in inventory['units'].items(): assert sha(units[name])==item['sha256'],name
 assert sha(H/'integer_to_string.cpp')==inventory['integer_to_string_sha256']
 units.update(entry=entry,report_provider=H/'report_provider.c',
  stx_common=source/'ypc/stbox/src/stx_common.cpp',stx_trusted=source/'ypc/stbox/src/tsgx/stx_common_trusted.cpp',
  stx_util=source/'ypc/stbox/src/tsgx/util.cpp',package=source/'ypc/core/src/core_t/ecommon/package.cpp',
  signer_verify=source/'ypc/core/src/core_t/ecommon/signer_verify.cpp')
 if kind=='analyzer':units.update(keymgr=source/'ypc/core/src/core_t/analyzer/internal/keymgr_session.cpp',
  enclave_hash=source/'ypc/core/src/core_t/analyzer/var/enclave_hash_var.cpp',
  version=source/'ypc/core/src/core_t/analyzer/analyzer_version.cpp')
 else:units.update(dh_responder=source/'ypc/stbox/src/tsgx/channel/dh_session_responder.cpp',
  seal=source/'ypc/stbox/src/tsgx/crypto/seal_sgx.cpp',ecc=source/'ypc/core/src/core_t/sgx_ecc/stdeth_ecc_impl.cpp')
 for n in ('algorithm','atomic','functional','hash','utility','vector','string','stdexcept','optional','any','variant','charconv','memory_eh'):
  units['cxx_'+n]=prepared/'src'/(n+'.cpp')
 units['cxx_integer_to_string']=H/'integer_to_string.cpp'
 if profile!='BASELINE':units['typeinfo']=R/'apps/cxx-abi/typeinfo.cpp'
 defs=set();unitflags={}
 for n,src in units.items():
  uf=list(flags)
  if src.suffix=='.c':
   uf=[f for f in uf if f not in ('-std=c++17','-fexceptions','-frtti','-nostdinc++')]
   index=uf.index(str(g/(stem+'_t.h')));del uf[index-1:index+1]
   uf+=['-std=c11']
  if n=='secp_library':uf+=['-I'+str(source/'include/ypc/stbox'),'-I'+str(source/'ypc/stbox/src/tsgx/secp256k1'),
    *['-D'+x for x in ('USE_NUM_NONE','USE_FIELD_5X52','HAVE___INT128','USE_FIELD_INV_BUILTIN','USE_SCALAR_4X64','USE_SCALAR_INV_BUILTIN','USE_LOW_HEAP')]]
  unitflags[n]=uf;ir=out/(n+'.frontend.ll')
  run(kind+'-'+n+'-frontend',['clang-21',*uf,'-S','-emit-llvm',src,'-o',ir],env)
  text=ir.read_text();defs.update(re.findall(r'^define .*?@([^ (]+)\(',text,re.M));defs.update(re.findall(r'^@([^ ]+) = .*?alias ',text,re.M))
 # The selected C formatter is rebuilt under the same preset/EH mode.
 caller=out/'format_inventory.cpp';caller.write_text('extern "C" int format_inventory(){return 0;}\n')
 fmt=out/'formatter';fenv=dict(env,ENCBOUND_CXX_EH_ENTRIES=str(g/'eh-entries.txt'))
 run(kind+'-formatter',[R/'tools/with-integration-defaults.sh','python3',R/'apps/libc-format/build.py',
  '--profile',profile,'--out-dir',fmt,'--caller',caller],fenv)
 lib=json.loads((fmt/'build.json').read_text());admitted=out/'admitted.txt'
 proxies=(g/'admitted-ocalls.txt').read_text().splitlines()
 names=defs|set(Path(lib['admitted']).read_text().splitlines())|set((g/'admitted-app.txt').read_text().splitlines())|set((g/'admitted-ocalls.txt').read_text().splitlines())
 admitted.write_text('\n'.join(sorted(names))+'\n'+(H/'admitted-services.txt').read_text()+(H/'full-admitted-services.txt').read_text()+''.join(n+' = encbound_yeez_proxy_'+n+'\n' for n in proxies))
 aenv=dict(env,ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CXX_EH_ENTRIES=str(g/'eh-entries.txt'))
 app=[]
 for n,src in units.items():
  obj=out/(n+'.o')
  cached=False
  if obj.with_suffix('.integration.json').exists() and Path(str(obj)+'.ownership.json').exists():
   oldunit=json.loads(obj.with_suffix('.integration.json').read_text());oldown=json.loads(Path(str(obj)+'.ownership.json').read_text())
   cached=(oldunit['frontend_flags'][-len(unitflags[n]):]==list(map(str,unitflags[n]))) and all(Path(p).exists() and sha(p)==h for p,h in oldunit['inputs'].items()) and sha(obj)==oldown['output_sha256'] and oldunit['object_sha256']==oldown['input_sha256'] and sha(obj.with_suffix('.checked.ll'))==oldunit['checked_ir_sha256'] and sha(obj.with_suffix('.input.ll'))==oldunit['input_ir_sha256']
  if cached:
   print(profile,kind+'-'+n,'verified cached object',flush=True);app.append(obj);continue
  run(kind+'-'+n,[R/'tools/with-integration-defaults.sh',R/'tools/encbound-cc.sh',src,obj,*unitflags[n]],aenv)
  placed=out/(n+'.placed.o');run(kind+'-'+n+'-place',[R/'tools/with-integration-defaults.sh',R/'tools/mark_appdata_sections.sh',obj,placed],aenv)
  placed.replace(obj);Path(str(placed)+'.ownership.json').replace(str(obj)+'.ownership.json');app.append(obj)
 app+=list(map(Path,lib['objects']))
 if options.compile_only:continue
 defines=['-DENCBOUND_CXX_BASELINE'] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
 if profile=='MAC27':defines+=['-DENCBOUND_MAC27']
 sources={'bridge':g/(stem+'_t.c'),'yeez_adapters':H/'adapters.c','full_adapters':H/'full_adapters.c',
  'kms_adapters':R/'apps/sgx-kms/adapters.c','cxx_allocations':R/'runtime/cxx_allocations.c','cxx_services':R/'runtime/cxx_services.c'}
 if profile!='BASELINE':sources={'early_bootstrap':R/'sdk/early_bootstrap.c',**sources,
  'boundary_support':R/'sdk/boundary_support.c','platform_layout':R/'sdk/platform_layout.c',
  **{n:R/f'runtime/{n}.c' for n in ('check_core','allocations','allocator','adapters','cxx_lifecycle')}}
 trusted=[]
 for n,src in sources.items():
  obj=out/(n+'.trusted.o');dep=obj.with_suffix('.d')
  cmd=['gcc',*[f for f in cflags if f not in ('-fno-vectorize','-fno-slp-vectorize')],'-isystem',str(P/'common/inc/internal'),*defines,'-MD','-MF',dep,'-c',src,'-o',obj]
  if n=='bridge' and profile!='BASELINE':cmd+=['-D'+p+'=encbound_yeez_proxy_'+p for p in proxies]
  run(kind+'-trusted-'+n,cmd)
  paths=shlex.split(dep.read_text().replace('\\\n',' ').partition(':')[2]);obj.with_suffix('.trusted.json').write_text(json.dumps(dict(command=list(map(str,cmd)),inputs={str(Path(p).resolve()):sha(p) for p in paths},object_sha256=sha(obj)),indent=2)+'\n');trusted.append(obj)
 if profile!='BASELINE':
  obj=out/'eh.trusted.o';dep=obj.with_suffix('.d');cmd=['clang++-21',*cflags,*defines,'-std=c++17','-fno-exceptions','-fno-rtti','-funwind-tables','-I'+str(O/'eh-headers'),'-isystem',str(P/'common/inc/internal'),'-MD','-MF',dep,'-c',R/'runtime/cxx_eh/runtime.cpp','-o',obj]
  run(kind+'-trusted-eh',cmd);paths=shlex.split(dep.read_text().replace('\\\n',' ').partition(':')[2]);obj.with_suffix('.trusted.json').write_text(json.dumps(dict(command=list(map(str,cmd)),inputs={str(Path(p).resolve()):sha(p) for p in paths},object_sha256=sha(obj)),indent=2)+'\n');trusted.append(obj)
 image=out/'enclave.so';linkmap=out/'enclave.map';libs=S/'lib64'
 link=['gcc',*trusted,*app,'-o',image,'-Wl,-z,relro,-z,now,-z,noexecstack','-Wl,--no-undefined','-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(libs),'-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive','-Wl,--start-group','-lsgx_tcxx','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group','-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry','-Wl,--export-dynamic','-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),'-Wl,--version-script='+str(R/'sdk/enclave.lds'),'-Wl,-T,'+str(R/'sdk/enclave_sections.lds')]
 run(kind+'-link',link);audit(image,app,trusted,linkmap)
 if profile!='BASELINE':bootstrap_audit(image)
 images[kind]=dict(image=str(image),sha256=sha(image),app=list(map(str,app)),trusted={str(p):sha(p) for p in trusted},link_command=list(map(str,link)))
(O/'build.json').write_text(json.dumps(dict(profile=profile,images=images,commands=commands),indent=2)+'\n')
print('YEEZ ORIGINAL ENCLAVE BUILD PASS',profile,flush=True)
