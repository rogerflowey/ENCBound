#!/usr/bin/env python3
"""Sign audited original enclaves and run the matched two-enclave host fixture."""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1]
S=Path(os.environ.get('SGX_SDK',R/'deps/sgxsdk'))
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--build',type=Path,default=R/'build/yeez/full-integration');p.add_argument('--profile',default='MAC27')
p.add_argument('--high',action='store_true');p.add_argument('--build-only',action='store_true')
p.add_argument('--signed-out',type=Path,default=None,help='separate signed/host output directory (default: <build>/<profile>/<low|high>)')
a=p.parse_args();O=a.build.resolve()/a.profile;build=json.loads((O/'build.json').read_text());assert len(build['images'])==2
out=a.signed_out.resolve() if a.signed_out else O/('high' if a.high else 'low');out.mkdir(parents=True,exist_ok=True);commands=[]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(name,cmd,env=None):
 cmd=list(map(str,cmd));q=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=240)
 log=out/(name+'.log');log.write_text(q.stdout+q.stderr);commands.append(dict(label=name,command=cmd,returncode=q.returncode,log=str(log),log_sha256=sha(log)))
 print(name,q.returncode,flush=True)
 if q.returncode:raise RuntimeError(log.read_text()[-9000:])
 return q
key=out/'test-key.pem';run('key',['openssl','genrsa','-out',key,'-3','3072'])
signed={}
for kind,base in [('analyzer','0x140000000' if a.high else '0x40000000'),('keymgr','0x180000000' if a.high else '0x80000000')]:
 image=Path(build['images'][kind]['image']);assert sha(image)==build['images'][kind]['sha256']
 config=out/(kind+'.xml');sizing=out/(kind+'-sizing.so');target=out/(kind+'.signed.so');template=R/'sdk/enclave.config.tmpl.xml'
 run(kind+'-config',['python3',R/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size','0x40000000','--out',config])
 run(kind+'-sizing',[S/'bin/x64/sgx_sign','sign','-key',key,'-enclave',image,'-out',sizing,'-config',config])
 extent=run(kind+'-extent',['python3',R/'tools/sgx_metadata.py','required','--signed',sizing]).stdout.strip()
 run(kind+'-final-config',['python3',R/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size',extent,'--out',config])
 run(kind+'-sign',[S/'bin/x64/sgx_sign','sign','-key',key,'-enclave',image,'-out',target,'-config',config])
 run(kind+'-metadata',['python3',R/'tools/sgx_metadata.py','verify','--signed',target,'--base',base,'--size',extent])
 signed[kind]=dict(image=str(target),sha256=sha(target),base=base,size=extent)
source=R/'build/paper-sources/yeez'
common=['-g','-O2','-I'+str(S/'include'),'-I'+str(source/'include')]
analyzer=O/'analyzer/generated';manager=O/'keymgr/generated'
run('analyzer-host-bridge',['gcc',*common,'-I'+str(analyzer),'-c',analyzer/'eparser_u.c','-o',out/'eparser_u.o'])
run('manager-host-bridge',['gcc',*common,'-Dstbox_common_version=keymgr_stbox_common_version','-I'+str(manager),'-c',manager/'ekeymgr_u.c','-o',out/'ekeymgr_u.o'])
secp=source/'ypc/stbox/src/tsgx/secp256k1'
run('host-secp',['gcc',*common,'-include','stdarg.h','-I'+str(source/'include/ypc/stbox'),'-I'+str(secp),
 *['-D'+x for x in ('USE_NUM_NONE','USE_FIELD_5X52','HAVE___INT128','USE_FIELD_INV_BUILTIN','USE_SCALAR_4X64','USE_SCALAR_INV_BUILTIN','USE_LOW_HEAP')],'-c',secp/'secp256k1.c','-o',out/'secp.o'])
run('host-keccak',['gcc',*common,'-c',source/'ypc/stbox/src/keccak/keccak.c','-o',out/'keccak.o'])
run('host-permissions',['gcc',*common,'-c',H/'host_permissions.c','-o',out/'permissions.o'])
host=out/'host';libs=S/'lib64'
run('host',['g++',*common,'-std=c++17','-Wno-deprecated-declarations','-I'+str(analyzer),'-I'+str(manager),H/'host.cpp',
 out/'eparser_u.o',out/'ekeymgr_u.o',out/'secp.o',out/'keccak.o',out/'permissions.o','-o',host,'-L'+str(libs),'-Wl,-rpath-link,'+str(libs),'-lsgx_urts_sim','-lpthread','-lcrypto'])
record=dict(profile=a.profile,high=a.high,signed=signed,host=str(host),host_sha256=sha(host),commands=commands)
(out/'results.json').write_text(json.dumps(record,indent=2)+'\n')
if not a.build_only:
 env=dict(os.environ,LD_LIBRARY_PATH=str(S/'sdk_libs')+':'+str(libs),YEEZ_VERBOSE='1',
    YEEZ_ANALYZER_BASE=signed['analyzer']['base'],YEEZ_MANAGER_BASE=signed['keymgr']['base'])
 q=run('run',[host,signed['analyzer']['image'],signed['keymgr']['image']],env)
 assert 'YEEZ ORIGINAL ANALYZER SDK SIM PASS' in q.stdout
 record.update(commands=commands,output=q.stdout,result='pass');(out/'results.json').write_text(json.dumps(record,indent=2)+'\n')
 print(q.stdout,flush=True)
