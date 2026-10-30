#!/usr/bin/env python3
"""Real SDK SIM lifecycle closure; all application units use the preset.

Build/sign recipe reduced from tests/early-bootstrap/run.py and apps/pre-stl.
The SDK still owns startup arrays and destructor registration/callback order.
"""
import hashlib
import json
import os
import resource
import subprocess
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BUILD=ROOT/'build/integration/cxx-lifecycle'
SDK=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PINNED=Path(os.environ.get('PINNED_SRC',str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
BUILD.mkdir(parents=True,exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(ROOT/'tools'))
from audit_app_globals import audit
from check_early_bootstrap import audit as startup_audit, initializers
from check_sdk_pins import SDK_BINARIES
from encbound_inventory import get_marker

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(name,cmd,*,env=None,expected=0):
    p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env,timeout=120)
    (BUILD/(name+'.log')).write_text(p.stdout+p.stderr)
    assert p.returncode==expected,(name,p.returncode,p.stdout,p.stderr)
    return p
def names(obj,flag):
    return {l.split()[-1] for l in subprocess.check_output(['nm',flag,str(obj)],text=True).splitlines() if l.strip()}

run('plugin',['make','-C',ROOT/'pass'])
run('generator',['make','-C',ROOT/'tools/edger8r'])
run('pins',['python3',ROOT/'tools/check_sdk_pins.py','--sdk',SDK,'--pinned',PINNED])
tcxx=SDK/'lib64/libsgx_tcxx.a'
assert digest(tcxx)=='50731a201df955b9fab2f4b6292c5c9004bcfc089fa7af4ad956a97bb8fa1a21'
rows=[]
for opt in ('O0','O2'):
 for serial in (False,True):
  for profile,base in [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),
                       ('MAC27','0x40000000'),('MAC27','0x140000000')]:
    key=f'{profile}-{base}-{opt}-'+('serial' if serial else 'sdk-guards')
    out=BUILD/key;out.mkdir(exist_ok=True);g=out/'generated'
    flags=['-m64','-'+opt,'-g','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections',
           '-fstack-protector-strong','-nostdinc','-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime'),
           '-I'+str(ROOT/'sdk'),'-I'+str(HERE),'-I'+str(g),'-I'+str(SDK/'include'),
           '-I'+str(SDK/'include/tlibc'),'-isystem',str(PINNED/'common/inc/internal')]
    cppflags=flags+['-x','c++','-std=c++17','-fno-exceptions','-fno-rtti','-fno-common','-fno-builtin']
    if serial: cppflags+=['-fno-threadsafe-statics']
    interface=ROOT/'tests/fixtures/pre-stl-interface.json'
    run(key+'-generate',['python3',ROOT/'tools/modified_bridge.py','--edl',HERE/'probe.edl',
       '--interface',interface,'--generator',ROOT/'build/edger8r/sgx_edger8r','--out-dir',g,
       '--profile',profile,'--search-path',SDK/'include','--cc','gcc','--layout-cc','clang-21',
       *['--cflag='+f for f in flags]])
    # Actual definitions only, including ODR callbacks and cross-unit methods.
    definitions=set()
    for n in ('app','other'):
        ir=out/(n+'.frontend.ll')
        run(key+'-'+n+'-frontend',['clang-21',*cppflags,'-S','-emit-llvm',HERE/(n+'.cpp'),'-o',ir])
        obj=out/(n+'.frontend.o')
        run(key+'-'+n+'-inventory',['clang-21','-c',ir,'-o',obj])
        definitions |= names(obj,'--defined-only')
    admitted=out/'admitted.txt';admitted.write_text('\n'.join(sorted(definitions))+'\n')
    env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CXX_LIFECYCLE='1')
    app=[]
    for n in ('app','other'):
        obj=out/(n+'.o')
        run(key+'-'+n,['/bin/sh',ROOT/'tools/with-integration-defaults.sh','env','ENCBOUND_CXX_LIFECYCLE=1',
            ROOT/'tools/encbound-cc.sh',HERE/(n+'.cpp'),obj,*cppflags],env=env)
        placed=out/(n+'.placed.o')
        run(key+'-'+n+'-place',['python3',ROOT/'tools/mark_app_globals.py',obj,placed])
        placed.replace(obj);Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
        app.append(obj)
    sources={'probe_t':g/'probe_t.c','trusted':HERE/'trusted.c','cxx_allocations':ROOT/'runtime/cxx_allocations.c'}
    defines=['-DENCBOUND_CXX_BASELINE'] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
    if profile=='MAC27':defines+=['-DENCBOUND_MAC27']
    if profile!='BASELINE':
        sources={'early_bootstrap':ROOT/'sdk/early_bootstrap.c',**sources,
            'boundary_support':ROOT/'sdk/boundary_support.c','platform_layout':ROOT/'sdk/platform_layout.c',
            **{n:ROOT/f'runtime/{n}.c' for n in ('check_core','allocations','allocator','adapters','cxx_lifecycle')}}
    trusted=[]
    for n,src in sources.items():
        obj=out/(n+'.o');run(key+'-'+n,['gcc',*flags,*defines,'-O2','-c',src,'-o',obj]);trusted.append(obj)
    # Link one application member from an actual archive. Extract it first only
    # for ownership accounting; the linker selects it from the archive itself.
    archive=out/'application.a';run(key+'-archive',['ar','rcs',archive,app[1]])
    image=out/'enclave.so';linkmap=out/'enclave.map';libs=SDK/'lib64'
    cmd=['gcc',*trusted,app[0],archive,'-o',image,'-Wl,-z,relro,-z,now,-z,noexecstack',
        '-Wl,--no-undefined','-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(libs),
        '-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive','-Wl,--start-group',
        '-lsgx_tcxx','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group',
        '-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry','-Wl,--export-dynamic',
        '-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),'-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')]
    run(key+'-link',cmd)
    audit(image,app,trusted,linkmap,archive_members={archive:[app[1]]})
    if profile!='BASELINE': startup_audit(image)
    # Closed symbol ownership and compiler/placement provenance for each unit.
    appdefs=set().union(*(names(o,'--defined-only') for o in app))
    services={n for o in trusted for n in names(o,'--defined-only') if n.startswith('encbound_')}
    allowed=appdefs|services|{'__stack_chk_fail'}
    if profile=='BASELINE':allowed|={'__cxa_atexit','__dso_handle','__cxa_guard_acquire','__cxa_guard_release'}
    units=[]
    for obj in app:
        assert names(obj,'--undefined-only')<=allowed,names(obj,'--undefined-only')-allowed
        assert get_marker(obj)==(None if profile=='BASELINE' else profile)
        unit=json.loads(obj.with_suffix('.integration.json').read_text())
        assert unit['settings']['ENCBOUND_CXX_LIFECYCLE']=='1'
        assert unit['settings']['ENCBOUND_PROTECTED_GLOBALS']=='1'
        for src,h in unit['inputs'].items():assert digest(Path(src))==h,src
        placement=json.loads(Path(str(obj)+'.ownership.json').read_text())
        assert unit['object_sha256']==placement['input_sha256']
        assert digest(obj.with_suffix('.checked.ll'))==unit['checked_ir_sha256']
        units.append(unit)
    archives={Path(l[5:]) for l in linkmap.read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.a')}
    assert archives=={archive,tcxx,*[SDK/p for p in SDK_BINARIES if p.endswith('.a')]}
    for a in archives-{archive,tcxx}:assert digest(a)==SDK_BINARIES['lib64/'+a.name]
    private=out/'test-key.pem';run(key+'-key',['openssl','genrsa','-out',private,'-3','3072'])
    sizing=out/'sizing.xml';template=ROOT/'sdk/enclave.config.tmpl.xml'
    run(key+'-sizing',['python3',ROOT/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size','0x40000000','--out',sizing])
    run(key+'-sizing-sign',[SDK/'bin/x64/sgx_sign','sign','-key',private,'-enclave',image,'-out',out/'sizing.so','-config',sizing])
    extent=run(key+'-extent',['python3',ROOT/'tools/sgx_metadata.py','required','--signed',out/'sizing.so']).stdout.strip()
    final=out/'final.xml'
    run(key+'-final',['python3',ROOT/'tools/sgx_metadata.py','render-config','--template',template,'--base',base,'--size',extent,'--out',final])
    signed=out/'enclave.signed.so'
    run(key+'-sign',[SDK/'bin/x64/sgx_sign','sign','-key',private,'-enclave',image,'-out',signed,'-config',final])
    run(key+'-metadata',['python3',ROOT/'tools/sgx_metadata.py','verify','--signed',signed,'--base',base,'--size',extent])
    host=out/'host'
    run(key+'-host',['gcc','-g','-O2','-I'+str(g),'-I'+str(SDK/'include'),HERE/'host.c',g/'probe_u.c',
        '-o',host,'-L'+str(libs),'-Wl,-rpath-link,'+str(libs),'-lsgx_urts_sim','-lpthread'])
    runenv=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libs),ENCBOUND_TEST_BASE=base)
    p=run(key+'-run',[host,signed],env=runenv)
    assert 'CXX LIFECYCLE SDK SIM PASS' in p.stdout
    rows.append(dict(mode='SDK SIM',profile=profile,base=base,frontend=opt,serial_guards=serial,
        image_sha256=digest(signed),units=units,archives={str(p):digest(p) for p in archives},
        initializers=initializers(signed),result='pass',link_command=list(map(str,cmd)),
        application_objects=list(map(str,app)),trusted_objects={str(p):digest(p) for p in trusted},
        loaded_image=str(signed),normal_ecalls=13))
    print(key,'PASS',flush=True)
(BUILD/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX LIFECYCLE SDK SIM MATRIX PASS',len(rows))
