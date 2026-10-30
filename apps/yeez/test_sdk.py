#!/usr/bin/env python3
"""Checked YeeZ service fixture with the real pinned SDK, SDK SIM only."""
import argparse,hashlib,json,os,resource,subprocess,sys
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1]
S=Path(os.environ.get('SGX_SDK',R/'deps/sgxsdk'))
P=Path(os.environ.get('PINNED_SRC',R/'deps/intel-sgx'))
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out',type=Path,default=R/'build/yeez/adapter-sim')
parser.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'])
a=parser.parse_args();B=a.out.resolve();assert B.is_relative_to(R/'build');B.mkdir(parents=True,exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(R/'tools'))
from audit_app_globals import audit
from encbound_inventory import get_marker
from check_sdk_pins import SDK_BINARIES
rows=[];commands=[]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(name,cmd,env=None):
 cmd=list(map(str,cmd));p=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=120)
 log=B/(name+'.log');log.write_text(p.stdout+p.stderr)
 commands.append(dict(label=name,command=cmd,returncode=p.returncode,log=str(log),log_sha256=sha(log)))
 assert p.returncode==0,(name,log.read_text()[-6000:])
 return p
run('pass',['make','-C',R/'pass']);run('generator',['make','-C',R/'tools/edger8r'])
run('pins',['python3',R/'tools/check_sdk_pins.py','--sdk',S,'--pinned',P])
for profile,base in [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),('MAC27','0x40000000'),('MAC27','0x140000000')]:
 if a.profile and a.profile!=profile:continue
 key=profile+'-'+base;out=B/key;out.mkdir(exist_ok=True);g=out/'generated'
 flags=['-m64','-O2','-g','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections',
        '-fstack-protector-strong','-nostdinc',*['-I'+str(p) for p in (R/'include',R/'sdk',R/'runtime',H,g,S/'include',S/'include/tlibc')],
        '-isystem',str(P/'common/inc/internal')]
 run(key+'-generate',['python3',R/'tools/modified_bridge.py','--edl',H/'test_sdk.edl',
     '--interface',R/'tests/fixtures/pre-stl-interface.json','--generator',R/'build/edger8r/sgx_edger8r',
     '--out-dir',g,'--profile',profile,'--search-path',S/'include',*['--cflag='+f for f in flags]])
 admitted=out/'admitted.txt';admitted.write_text((g/'admitted-app.txt').read_text()+
     (H/'admitted-services.txt').read_text()+''.join(f'yeez_peer_{n} = encbound_yeez_peer_{n}\n' for n in ('msg1','msg2','key')))
 env={k:v for k,v in os.environ.items() if not k.startswith('ENCBOUND_')}
 env.update(ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(admitted))
 app=out/'application.o'
 run(key+'-application',[R/'tools/with-integration-defaults.sh',R/'tools/encbound-cc.sh',
     H/'test_sdk_app.c',app,*flags,'-fno-common','-fno-builtin'],env)
 placed=out/'application.placed.o'
 run(key+'-place',[R/'tools/with-integration-defaults.sh',R/'tools/mark_appdata_sections.sh',app,placed],env)
 placed.replace(app);Path(str(placed)+'.ownership.json').replace(str(app)+'.ownership.json')
 unit=json.loads(app.with_suffix('.integration.json').read_text())
 assert get_marker(app)==(None if profile=='BASELINE' else profile)
 for path,expected in unit['inputs'].items():assert sha(path)==expected,path
 sources={'yeez_adapters':H/'adapters.c','peer':H/'test_sdk_peer.c','bridge':g/'test_sdk_t.c'}
 if profile!='BASELINE':
  sources.update({'boundary_support':R/'sdk/boundary_support.c','platform_layout':R/'sdk/platform_layout.c',
   **{n:R/f'runtime/{n}.c' for n in ('check_core','allocations','allocator','adapters')}})
 defines=[] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
 if profile=='MAC27':defines+=['-DENCBOUND_MAC27']
 trusted=[]
 for n,src in sources.items():
  obj=out/(n+'.o');dep=out/(n+'.d')
  command=['gcc',*flags,*defines,'-MD','-MF',dep,'-c',src,'-o',obj]
  run(key+'-'+n,command)
  import shlex
  inputs=shlex.split(dep.read_text().replace('\\\n',' ').partition(':')[2])
  obj.with_suffix('.trusted.json').write_text(json.dumps(dict(command=list(map(str,command)),
      inputs={str(Path(p).resolve()):sha(p) for p in inputs},object_sha256=sha(obj)),indent=2)+'\n')
  trusted.append(obj)
 image=out/'enclave.so';linkmap=out/'enclave.map';libs=S/'lib64'
 command=['gcc',*trusted,app,'-o',image,'-Wl,-z,relro,-z,now,-z,noexecstack','-Wl,--no-undefined',
     '-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(libs),'-Wl,--whole-archive','-lsgx_trts_sim',
     '-Wl,--no-whole-archive','-Wl,--start-group','-lsgx_tcxx','-lsgx_tstdc','-lsgx_tcrypto',
     '-lsgx_tservice_sim','-Wl,--end-group','-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry',
     '-Wl,--export-dynamic','-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),
     '-Wl,--version-script='+str(R/'sdk/enclave.lds'),'-Wl,-T,'+str(R/'sdk/enclave_sections.lds')]
 run(key+'-link',command);audit(image,[app],trusted,linkmap)
 tcxx=libs/'libsgx_tcxx.a'
 assert sha(tcxx)=='50731a201df955b9fab2f4b6292c5c9004bcfc089fa7af4ad956a97bb8fa1a21'
 archives={Path(line[5:]) for line in linkmap.read_text().splitlines() if line.startswith('LOAD ') and line.endswith('.a')}
 assert archives=={tcxx,*[S/name for name in SDK_BINARIES if name.endswith('.a')]}
 for name,expected in SDK_BINARIES.items():assert sha(S/name)==expected
 private=out/'test-key.pem';run(key+'-key',['openssl','genrsa','-out',private,'-3','3072'])
 template=R/'sdk/enclave.config.tmpl.xml';sizing=out/'sizing.xml';final=out/'final.xml';signed=out/'enclave.signed.so'
 run(key+'-sizing',['python3',R/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size','0x40000000','--out',sizing])
 run(key+'-sizing-sign',[S/'bin/x64/sgx_sign','sign','-key',private,'-enclave',image,'-out',out/'sizing.so','-config',sizing])
 extent=run(key+'-extent',['python3',R/'tools/sgx_metadata.py','required','--signed',out/'sizing.so']).stdout.strip()
 run(key+'-config',['python3',R/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size',extent,'--out',final])
 run(key+'-sign',[S/'bin/x64/sgx_sign','sign','-key',private,'-enclave',image,'-out',signed,'-config',final])
 run(key+'-metadata',['python3',R/'tools/sgx_metadata.py','verify','--signed',signed,'--base',base,'--size',extent])
 audit(signed,[app],trusted,linkmap)
 host=out/'host'
 run(key+'-host',['gcc','-g','-O2','-I'+str(g),'-I'+str(S/'include'),H/'test_sdk_host.c',g/'test_sdk_u.c',
     '-o',host,'-L'+str(libs),'-Wl,-rpath-link,'+str(libs),'-lsgx_urts_sim','-lpthread'])
 p=run(key+'-run',[host,signed],dict(os.environ,LD_LIBRARY_PATH=str(S/'sdk_libs')+':'+str(libs),ENCBOUND_TEST_BASE=base))
 assert 'YEEZ SDK ADAPTER SIM PASS calls=45' in p.stdout
 rows.append(dict(mode='SDK SIM service fixture',profile=profile,base=base,ecalls=45,
     image=str(signed),image_sha256=sha(signed),app=str(app),unit=unit,
     trusted={str(obj):sha(obj) for obj in trusted},link_command=list(map(str,command)),
     result=p.stdout.strip(),host_sha256=sha(host)))
 (B/'results.json').write_text(json.dumps(dict(rows=rows,commands=commands,hardware=False,yeez_workflow=False,
     inputs={str(p):sha(p) for p in (Path(__file__),H/'adapters.c',H/'adapters.h',H/'test_sdk_app.c',H/'test_sdk_peer.c',H/'test_sdk_host.c',H/'test_sdk.edl')}),indent=2)+'\n')
 print(key,p.stdout.strip(),flush=True)
