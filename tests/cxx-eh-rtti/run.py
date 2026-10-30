#!/usr/bin/env python3
"""Real SDK SIM lifecycle closure; all application units use the preset.

Build/sign recipe reduced from tests/early-bootstrap/run.py and apps/pre-stl.
The SDK still owns startup arrays and destructor registration/callback order.
"""
import argparse
import hashlib
import json
import os
import resource
import re
import shlex
import subprocess
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BUILD=ROOT/'build/integration/cxx-eh-rtti'
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
def trusted_compile(name,command,obj):
    command=[*command,'-MD','-MF',obj.with_suffix('.d')]
    run(name,command)
    dependency=obj.with_suffix('.d').read_text().replace('\\\n','')
    paths=shlex.split(dependency.split(':',1)[1])
    record=dict(command=list(map(str,command)),inputs={str(Path(p).resolve()):digest(Path(p)) for p in paths},object_sha256=digest(obj))
    obj.with_suffix('.trusted.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

run('plugin',['make','-C',ROOT/'pass'])
run('generator',['make','-C',ROOT/'tools/edger8r'])
run('pins',['python3',ROOT/'tools/check_sdk_pins.py','--sdk',SDK,'--pinned',PINNED])
tcxx=SDK/'lib64/libsgx_tcxx.a'
assert digest(tcxx)=='50731a201df955b9fab2f4b6292c5c9004bcfc089fa7af4ad956a97bb8fa1a21'
ap=argparse.ArgumentParser()
ap.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'])
ap.add_argument('--frontend',choices=['O0','O2'])
ap.add_argument('--codegen',choices=['O0','O2'],default='O2')
ap.add_argument('--libcxx',action='store_true')
options=ap.parse_args()
if options.libcxx:run('libcxx-prepare',['python3',ROOT/'apps/libcxx/prepare.py'])
run('eh-headers',['python3',ROOT/'runtime/cxx_eh/prepare.py','--out',BUILD/'abi-headers'])
run('cxx-headers',['python3',ROOT/'tools/prepare_cxx_headers.py','--sdk',SDK,'--out',BUILD/'headers'])
rows=[]
for opt in ('O0','O2'):
 for serial in (False,):
  for profile,base in [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),
                       ('MAC27','0x40000000'),('MAC27','0x140000000')]:
    if options.profile and profile!=options.profile: continue
    if options.frontend and opt!=options.frontend: continue
    key=f'{profile}-{base}-{opt}-{options.codegen}'+('-libcxx' if options.libcxx else '')
    out=BUILD/key;out.mkdir(exist_ok=True);g=out/'generated'
    flags=['-m64','-'+opt,'-g','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections',
           '-fstack-protector-strong','-nostdinc','-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime'),
           '-I'+str(ROOT/'sdk'),'-I'+str(HERE),'-I'+str(g),'-I'+str(SDK/'include'),
           '-I'+str(SDK/'include/tlibc'),'-isystem',str(PINNED/'common/inc/internal')]
    cppflags=flags+['-x','c++','-std=c++17','-fexceptions','-frtti','-nostdinc++','-I'+str(BUILD/'headers'),'-I'+str(SDK/'include/libcxx'),'-fno-common','-fno-builtin']
    if options.libcxx:
        cppflags.insert(0,'-I'+str(ROOT/'build/libcxx/headers'))
        cppflags.append('-DEH_LIBCXX=1')
        cppflags += ['-D'+n+'=app_libcxx_'+n for n in ('memchr','wmemcpy','wmemmove','wmemset','wmemchr','wmemcmp','wcslen')]
    if serial: cppflags+=['-fno-threadsafe-statics']
    interface=ROOT/'tests/fixtures/pre-stl-interface.json'
    run(key+'-generate',['python3',ROOT/'tools/modified_bridge.py','--edl',HERE/'probe.edl',
       '--interface',interface,'--generator',ROOT/'build/edger8r/sgx_edger8r','--out-dir',g,
       '--profile',profile,'--cxx-eh','--search-path',SDK/'include','--cc','gcc','--layout-cc','clang-21',
       *['--cflag='+f for f in flags]])
    # Actual definitions only, including ODR callbacks and cross-unit methods.
    definitions=set()
    app_sources={'app':HERE/'app.cpp','other':HERE/'other.cpp'}
    if profile!='BASELINE' and not options.libcxx:app_sources['typeinfo']=ROOT/'apps/cxx-abi/typeinfo.cpp'
    for n,src in app_sources.items():
        ir=out/(n+'.frontend.ll')
        run(key+'-'+n+'-frontend',['clang-21',*cppflags,'-S','-emit-llvm',src,'-o',ir])
        obj=out/(n+'.frontend.o')
        run(key+'-'+n+'-inventory',['clang-21','-c',ir,'-o',obj])
        definitions |= names(obj,'--defined-only')
    library=[]
    if options.libcxx:
        library_env=dict(os.environ,ENCBOUND_CXX_EH='1',ENCBOUND_CXX_EH_ENTRIES=str(g/'eh-entries.txt'))
        run(key+'-libcxx',[ROOT/'tools/with-integration-defaults.sh','env','ENCBOUND_CODEGEN_OPT=-'+options.codegen,
            'python3',ROOT/'apps/libcxx/build.py','--profile',profile,'--frontend',opt,'--out-dir',out/'libcxx',
            '--caller',HERE/'app.cpp','--caller',HERE/'other.cpp','--caller-flag=-DEH_LIBCXX=1'],env=library_env)
        librecord=json.loads((out/'libcxx/build.json').read_text())
        library=list(map(Path,librecord['objects']))
        definitions.update(Path(librecord['admitted']).read_text().split())
    admitted=out/'admitted.txt';admitted.write_text('\n'.join(sorted(definitions))+'\n')
    env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CXX_LIFECYCLE='1',ENCBOUND_CXX_EH='1',ENCBOUND_CXX_EH_ENTRIES=str(g/'eh-entries.txt'))
    app=[]
    for n,src in app_sources.items():
        obj=out/(n+'.o')
        run(key+'-'+n,['/bin/sh',ROOT/'tools/with-integration-defaults.sh','env','ENCBOUND_CXX_LIFECYCLE=1','ENCBOUND_CODEGEN_OPT=-'+options.codegen,
            ROOT/'tools/encbound-cc.sh',src,obj,*cppflags],env=env)
        placed=out/(n+'.placed.o')
        run(key+'-'+n+'-place',['python3',ROOT/'tools/mark_app_globals.py',obj,placed])
        placed.replace(obj);Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
        app.append(obj)
    app+=library
    sources={'probe_t':g/'probe_t.c','cxx_allocations':ROOT/'runtime/cxx_allocations.c','cxx_services':ROOT/'runtime/cxx_services.c'}
    defines=['-DENCBOUND_CXX_BASELINE'] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
    if profile=='MAC27':defines+=['-DENCBOUND_MAC27']
    if profile!='BASELINE':
        sources={'early_bootstrap':ROOT/'sdk/early_bootstrap.c',**sources,
            'boundary_support':ROOT/'sdk/boundary_support.c','platform_layout':ROOT/'sdk/platform_layout.c',
            **{n:ROOT/f'runtime/{n}.c' for n in ('check_core','allocations','allocator','adapters','cxx_lifecycle')}}
    trusted=[];trusted_units=[]
    for n,src in sources.items():
        obj=out/(n+'.o');trusted_units.append(trusted_compile(key+'-'+n,['gcc',*flags,*defines,'-O2','-c',src,'-o',obj],obj));trusted.append(obj)
    if profile!='BASELINE':
        obj=out/'cxx_eh_runtime.o'
        trusted_units.append(trusted_compile(key+'-eh-runtime',['clang++-21',*flags,*defines,'-O2','-std=c++17','-fno-exceptions','-fno-rtti','-funwind-tables','-I'+str(BUILD/'abi-headers'),'-c',ROOT/'runtime/cxx_eh/runtime.cpp','-o',obj],obj))
        trusted.append(obj)
    # Link one application member from an actual archive. Extract it first only
    # for ownership accounting; the linker selects it from the archive itself.
    archive=out/'application.a';archive.unlink(missing_ok=True)
    run(key+'-archive',['ar','rcs',archive,*app[1:]])
    image=out/'enclave.so';linkmap=out/'enclave.map';libs=SDK/'lib64'
    cmd=['gcc',*trusted,app[0],*(['-Wl,--whole-archive',archive,'-Wl,--no-whole-archive'] if options.libcxx else [archive]),'-o',image,'-Wl,-z,relro,-z,now,-z,noexecstack',
        '-Wl,--no-undefined','-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(libs),
        '-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive','-Wl,--start-group',
        '-lsgx_tcxx','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group',
        '-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry','-Wl,--export-dynamic',
        '-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),'-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')]
    run(key+'-link',cmd)
    audit(image,app,trusted,linkmap,archive_members={archive:app[1:]})
    if profile!='BASELINE' and any('llvm.global_ctors' in obj.with_suffix('.input.ll').read_text() for obj in app): startup_audit(image)
    # Closed symbol ownership and compiler/placement provenance for each unit.
    appdefs=set().union(*(names(o,'--defined-only') for o in app))
    services={n for o in trusted for n in names(o,'--defined-only') if n.startswith('encbound_')}
    allowed=appdefs|services|{'__stack_chk_fail','memcpy','memmove','memset'}
    if profile=='BASELINE':allowed|={'__cxa_atexit','__dso_handle','__cxa_guard_acquire','__cxa_guard_release'}
    units=[]
    if profile=='BASELINE':allowed|=names(tcxx,'--defined-only')|names(SDK/'lib64/libsgx_tstdc.a','--defined-only')|{'abort','_Unwind_Resume'}
    else:allowed|={'_Unwind_Resume'}
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
    run(key+'-host',['gcc','-g','-O2',*(['-DEH_LIBCXX=1'] if options.libcxx else []),'-I'+str(g),'-I'+str(SDK/'include'),HERE/'host.c',g/'probe_u.c',
        '-o',host,'-L'+str(libs),'-Wl,-rpath-link,'+str(libs),'-lsgx_urts_sim','-lpthread'])
    runenv=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libs),ENCBOUND_TEST_BASE=base)
    p=run(key+'-run',[host,signed],env=runenv)
    assert 'ENCBound SDK SIM EH/RTTI PASS' in p.stdout
    normal_ecalls=int(re.search(r'PASS: (\d+) ECALLs',p.stdout).group(1))
    null_regression=False
    if profile!='BASELINE':
        p=run(key+'-null-virtual',[host,signed,'130'],env=runenv)
        assert 'CONTROL_RETURN status=0x0 value=1' in p.stdout
        null_regression=True
    rows.append(dict(mode='SDK SIM',profile=profile,base=base,frontend=opt,serial_guards=serial,
        image_sha256=digest(signed),units=units,archives={str(p):digest(p) for p in archives},
        initializers=(initializers(signed) if 'INIT_ARRAY' in subprocess.check_output(['readelf','-dW',str(signed)],text=True) else []),result='pass',link_command=list(map(str,cmd)),
        application_objects=list(map(str,app)),trusted_objects={str(p):digest(p) for p in trusted},
        loaded_image=str(signed),normal_ecalls=normal_ecalls,null_virtual_pointer_regression=null_regression,codegen=options.codegen,libcxx=options.libcxx,trusted_units=trusted_units,
        host_sha256=digest(host),loaded_permissions='pass'))
    print(key,'PASS',flush=True)
(BUILD/('results-'+(options.profile or 'all')+'-'+(options.frontend or 'all')+'-'+options.codegen+('-libcxx' if options.libcxx else '')+'.json')).write_text(json.dumps(rows,indent=2)+'\n')
print('CXX EH/RTTI SDK SIM MATRIX PASS',len(rows))
