#!/usr/bin/env python3
"""Isolated VLA SDK SIM integration. Build/sign scaffolding is reduced from
tests/early-bootstrap/run.py and apps/pre-stl (SDK sample origin in docs/reference/SOURCES.md).
All application code uses the new-integration preset; runtime stays trusted.
"""
import argparse,hashlib,json,os,resource,subprocess,sys
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1];B=R/'build/integration/vla/sdk'
SDK=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PIN=Path(os.environ.get('PINNED_SRC',str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
B.mkdir(parents=True,exist_ok=True);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(R/'tools'))
from audit_app_globals import audit
from check_sdk_pins import SDK_BINARIES
from encbound_inventory import get_marker
p=argparse.ArgumentParser();p.add_argument('--attribute',action='store_true');args=p.parse_args()
commands=[];rows=[]
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def run(name,cmd,env=None,expected=0):
    p=subprocess.run(list(map(str,cmd)),text=True,capture_output=True,env=env,timeout=120)
    (B/(name+'.log')).write_text(p.stdout+p.stderr)
    commands.append(dict(command=list(map(str,cmd)),returncode=p.returncode,log=name+'.log'))
    assert p.returncode==expected,(name,p.returncode,p.stdout,p.stderr)
    return p.stdout+p.stderr
if args.attribute:
 for profile in ('RADIX_ONLY','MAC27'):
    out=B/(profile+'-0x40000000-O2')
    env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'))
    for mode,code,origin in [(3,6,'encbound_stack_prepare'),(4,4,'encbound_require'),(6,6,'encbound_stack_prepare')]:
        log=run(profile+'-attribution-'+str(mode),['gdb','-q','-batch','-ex','set pagination off',
            '-ex','add-symbol-file '+str(out/'enclave.so')+' -o 0x40000000',
            '-ex','run','-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt',
            '--args',out/'host',out/'enclave.signed.so',str(mode)],env)
        assert 'SIGILL' in log and f'ABORT_CODE {code}\n' in log and origin in log and 'vla_' in log,log
        rows.append(dict(mode='SDK SIM debugger attribution',profile=profile,control=mode,abort_code=code,
            origin=origin,result='pass',image_sha256=digest(out/'enclave.signed.so')))
 (B/'attribution.json').write_text(json.dumps(dict(rows=rows,commands=commands),indent=2)+'\n')
 print('VLA SDK SIM ATTRIBUTION PASS',len(rows));sys.exit(0)

run('plugin',['make','-C',R/'pass']);run('generator',['make','-C',R/'tools/edger8r'])
run('pins',['python3',R/'tools/check_sdk_pins.py','--sdk',SDK,'--pinned',PIN])
for opt in ('O0','O2'):
 for profile,base in [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),
                      ('MAC27','0x40000000'),('MAC27','0x140000000')]:
    key=f'{profile}-{base}-{opt}';out=B/key;out.mkdir(exist_ok=True);g=out/'generated'
    flags=['-m64','-'+opt,'-g','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections',
        '-fstack-protector-strong','-nostdinc','-I'+str(R/'include'),'-I'+str(R/'runtime'),
        '-I'+str(R/'sdk'),'-I'+str(g),'-I'+str(SDK/'include'),'-I'+str(SDK/'include/tlibc'),
        '-isystem',str(PIN/'common/inc/internal')]
    run(key+'-generate',['python3',R/'tools/modified_bridge.py','--edl',H/'probe.edl',
        '--interface',R/'tests/fixtures/pre-stl-interface.json','--generator',R/'build/edger8r/sgx_edger8r',
        '--out-dir',g,'--profile',profile,'--search-path',SDK/'include','--cc','gcc','--layout-cc','clang-21',
        *['--cflag='+f for f in flags]])
    admitted=out/'admitted.txt';admitted.write_text('vla_observe\nvla_edge\nvla_destroyed\n')
    env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(admitted))
    obj=out/'app.o'
    run(key+'-app',[R/'tools/with-integration-defaults.sh',R/'tools/encbound-cc.sh',H/'app.c',obj,
        *flags,'-Xclang','-disable-O0-optnone','-fno-common','-fno-builtin'],env)
    placed=out/'placed.o';run(key+'-place',['python3',R/'tools/mark_app_globals.py',obj,placed])
    placed.replace(obj);Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
    unit=json.loads(obj.with_suffix('.integration.json').read_text())
    assert unit['settings']['ENCBOUND_VLA']=='1' and unit['settings']['ENCBOUND_PROTECTED_GLOBALS']=='1'
    for src,h in unit['inputs'].items():assert digest(src)==h,src
    assert get_marker(obj)==(None if profile=='BASELINE' else profile)
    cpp=out/'cpp.o'
    run(key+'-cpp',[R/'tools/with-integration-defaults.sh',R/'tools/encbound-cc.sh',H/'app.cpp',cpp,
        *flags,'-x','c++','-std=c++17','-fno-exceptions','-fno-rtti','-Xclang','-disable-O0-optnone',
        '-fno-common','-fno-builtin'],env)
    run(key+'-cpp-place',['python3',R/'tools/mark_app_globals.py',cpp,placed])
    placed.replace(cpp);Path(str(placed)+'.ownership.json').replace(Path(str(cpp)+'.ownership.json'))
    cpp_unit=json.loads(cpp.with_suffix('.integration.json').read_text())
    assert cpp_unit['settings']['ENCBOUND_VLA']=='1'
    for src,h in cpp_unit['inputs'].items():assert digest(src)==h,src
    assert get_marker(cpp)==(None if profile=='BASELINE' else profile)
    sources={'probe_t':g/'probe_t.c','trusted':H/'trusted.c','observer':H/'observer.c'}
    defines=[] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED','-DPROTECTED']
    if profile=='MAC27':defines+=['-DENCBOUND_MAC27']
    if profile!='BASELINE':
        sources.update(boundary_support=R/'sdk/boundary_support.c',platform_layout=R/'sdk/platform_layout.c',
            **{n:R/f'runtime/{n}.c' for n in ('check_core','allocations','allocator','adapters')})
    trusted=[]
    for name,src in sources.items():
        o=out/(name+'.o');run(key+'-'+name,['gcc',*flags,*defines,'-O2','-fstack-usage','-c',src,'-o',o]);trusted.append(o)
    def symbols(obj,flag):
        return {l.split()[-1] for l in subprocess.check_output(['nm',flag,str(obj)],text=True).splitlines() if l.strip()}
    allowed=symbols(obj,'--defined-only')|symbols(cpp,'--defined-only')|{'__stack_chk_fail'}
    allowed|={s for t in trusted for s in symbols(t,'--defined-only')}
    assert symbols(obj,'--undefined-only')<=allowed,symbols(obj,'--undefined-only')-allowed
    assert symbols(cpp,'--undefined-only')<=allowed,symbols(cpp,'--undefined-only')-allowed
    image=out/'enclave.so';linkmap=out/'enclave.map';libs=SDK/'lib64'
    link=['gcc',*trusted,obj,cpp,'-o',image,'-Wl,-z,relro,-z,now,-z,noexecstack','-Wl,--no-undefined',
        '-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(libs),'-Wl,--whole-archive','-lsgx_trts_sim',
        '-Wl,--no-whole-archive','-Wl,--start-group','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim',
        '-Wl,--end-group','-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry','-Wl,--export-dynamic',
        '-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(R/'sdk/enclave.lds'),'-Wl,-T,'+str(R/'sdk/enclave_sections.lds')]
    run(key+'-link',link);audit(image,[obj,cpp],trusted,linkmap)
    run(key+'-link-pins',['python3',R/'tools/check_sdk_pins.py','--sdk',SDK,'--pinned',PIN,'--link-map',linkmap])
    for path,h in SDK_BINARIES.items():
        if path.endswith('.a'):assert digest(SDK/path)==h,path
    private=out/'test-key.pem';run(key+'-key',['openssl','genrsa','-out',private,'-3','3072'])
    template=R/'sdk/enclave.config.tmpl.xml';sizing=out/'sizing.xml'
    run(key+'-sizing',['python3',R/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size','0x40000000','--out',sizing])
    run(key+'-sizing-sign',[SDK/'bin/x64/sgx_sign','sign','-key',private,'-enclave',image,'-out',out/'sizing.so','-config',sizing])
    extent=run(key+'-extent',['python3',R/'tools/sgx_metadata.py','required','--signed',out/'sizing.so']).strip()
    final=out/'final.xml';run(key+'-config',['python3',R/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size',extent,'--out',final])
    signed=out/'enclave.signed.so';run(key+'-sign',[SDK/'bin/x64/sgx_sign','sign','-key',private,'-enclave',image,'-out',signed,'-config',final])
    run(key+'-metadata',['python3',R/'tools/sgx_metadata.py','verify','--signed',signed,'--base',base,'--size',extent])
    host=out/'host';run(key+'-host',['gcc','-g','-O2','-I'+str(g),'-I'+str(SDK/'include'),H/'host.c',g/'probe_u.c',
        '-o',host,'-L'+str(libs),'-Wl,-rpath-link,'+str(libs),'-lsgx_urts_sim','-lpthread'])
    runenv=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libs))
    text=run(key+'-run',[host,signed],runenv);assert 'VLA SDK SIM PASS' in text
    rows.append(dict(mode='SDK SIM',profile=profile,base=base,frontend=opt,codegen='O2',result='pass',
        normal_ecalls=6,unit=unit,cpp_unit=cpp_unit,image_sha256=digest(signed),linkmap_sha256=digest(linkmap),
        trusted_objects={str(p):digest(p) for p in trusted},link_command=list(map(str,link))))
    print(key,'PASS',flush=True)
inputs=[*H.glob('*.*'),R/'pass/encbound_vla.h',R/'pass/encbound_pass.cpp',R/'build/pass/encbound_pass.so',
    R/'tools/encbound-cc.sh',R/'config/integration.env',*R.glob('runtime/*.[ch]'),*R.glob('include/*.h')]
(B/'results.json').write_text(json.dumps(dict(rows=rows,commands=commands,inputs={str(p):digest(p) for p in inputs}),indent=2)+'\n')
print('VLA SDK SIM MATRIX PASS',len(rows))
