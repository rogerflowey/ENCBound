#!/usr/bin/env python3
"""Build ctor/dtor slot-crossing controls; use --attribute for GDB traces."""
import argparse,hashlib,json,os,resource,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
B=ROOT/'build/integration/cxx-lifecycle'
SDK=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
sys.path.insert(0,str(ROOT/'tools'))
from audit_app_globals import audit
from check_early_bootstrap import audit as startup_audit
p=argparse.ArgumentParser();p.add_argument('--attribute',action='store_true');args=p.parse_args()
resource.setrlimit(resource.RLIMIT_CORE,(0,0));rows=[]
def run(name,cmd,*,env=None,expected=0):
    p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env,timeout=90)
    (B/(name+'.log')).write_text(p.stdout+p.stderr)
    assert p.returncode==expected,(name,p.returncode,p.stdout,p.stderr)
    return p.stdout+p.stderr
normal=json.loads((B/'results.json').read_text())
for profile in ('RADIX_ONLY','MAC27'):
 row=next(r for r in normal if r['profile']==profile and r['base']=='0x40000000' and r['frontend']=='O2' and not r['serial_guards'])
 out=B/(profile+'-0x40000000-O2-sdk-guards')
 for fault,case,origin in [(1,'constructor-range','Item::Item'),(2,'destructor-range','Item::~Item')]:
    target=out/case;target.mkdir(exist_ok=True)
    if not args.attribute:
        objects=[]
        for i,n in enumerate(('app','other')):
            obj=target/(n+'.o')
            env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(out/'admitted.txt'))
            run(profile+'-'+case+'-'+n,[ROOT/'tools/with-integration-defaults.sh',
                ROOT/'tools/encbound-cc.sh',HERE/(n+'.cpp'),obj,*row['units'][i]['frontend_flags'],
                '-DLIFECYCLE_FAULT='+str(fault)],env=env)
            placed=target/(n+'.placed.o')
            run(profile+'-'+case+'-'+n+'-place',['python3',ROOT/'tools/mark_app_globals.py',obj,placed])
            placed.replace(obj);Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
            objects.append(obj)
        archive=target/'application.a';run(profile+'-'+case+'-archive',['ar','rcs',archive,objects[1]])
        image=target/'enclave.so';linkmap=target/'enclave.map'
        command=[str(objects[0]) if x==row['application_objects'][0] else
                 str(archive) if x==str(out/'application.a') else str(image) if x==str(out/'enclave.so') else
                 '-Wl,-Map,'+str(linkmap) if x=='-Wl,-Map,'+str(out/'enclave.map') else x
                 for x in row['link_command']]
        run(profile+'-'+case+'-link',command)
        audit(image,objects,[Path(p) for p in row['trusted_objects']],linkmap,archive_members={archive:[objects[1]]})
        startup_audit(image)
        signed=target/'enclave.signed.so'
        run(profile+'-'+case+'-sign',[SDK/'bin/x64/sgx_sign','sign','-key',out/'test-key.pem',
            '-enclave',image,'-out',signed,'-config',out/'final.xml'])
        env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'),ENCBOUND_TEST_BASE='0x40000000')
        run(profile+'-'+case+'-run',[out/'host',signed],env=env,expected=-4)
    else:
        signed=target/'enclave.signed.so';image=target/'enclave.so'
        env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'),ENCBOUND_TEST_BASE='0x40000000')
        log=run(profile+'-'+case+'-attribution',['gdb','-q','-batch','-ex','set pagination off',
            '-ex','add-symbol-file '+str(image)+' -o 0x40000000','-ex','run',
            '-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt','--args',out/'host',signed],env=env)
        assert 'ABORT_CODE 4\n' in log and 'encbound_abort' in log and 'encbound_require' in log and origin in log,log
    rows.append(dict(mode='SDK SIM',profile=profile,case=case,image_sha256=hashlib.sha256(signed.read_bytes()).hexdigest(),
        result='pass; RANGE 4 attributed at '+origin if args.attribute else 'SIGILL; attribution required'))
(B/('protection-attributed.json' if args.attribute else 'protection.json')).write_text(json.dumps(rows,indent=2)+'\n')
print('CXX LIFECYCLE SDK SIM PROTECTION',len(rows),'controls', 'attributed PASS' if args.attribute else 'built and terminated')
