#!/usr/bin/env python3
"""Pinned sgx-fs SDK SIM closure; original source and EDL are read only.

Build/sign recipe reduced from tests/early-bootstrap/run.py and apps/pre-stl.
The SDK still owns startup arrays and destructor registration/callback order.
"""
import argparse
import hashlib
import json
import os
import resource
import shlex
import subprocess
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
ap=argparse.ArgumentParser()
ap.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'])
ap.add_argument('--base',choices=['0x40000000','0x140000000'])
ap.add_argument('--source',type=Path,default=ROOT/'build/sgx-fs/source')
ap.add_argument('--build-dir',type=Path,default=ROOT/'build/sgx-fs/repo-local-v1')
options=ap.parse_args()
options.source=options.source.resolve()
BUILD=options.build_dir.resolve()
SDK=Path(os.environ.get('SGX_SDK',ROOT/'build/sgx-fs/deps/sdk-package/package')).resolve()
PINNED=Path(os.environ.get('PINNED_SRC',ROOT/'build/sgx-fs/deps/intel-sgx')).resolve()
for path in (BUILD,SDK,PINNED,options.source):
    assert path.is_relative_to(ROOT), 'sgx-fs inputs/outputs must stay in this repository: '+str(path)
BUILD.mkdir(parents=True,exist_ok=True)
os.environ.update(SGX_SDK=str(SDK),PINNED_SRC=str(PINNED),ENCBOUND_LIBCXX_PREPARED=str(BUILD/'libcxx-prepared'),TMPDIR=str(BUILD))
PREPARED=BUILD/'libcxx-prepared'
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sys.path.insert(0,str(ROOT/'tools'))
from audit_app_globals import audit
from check_early_bootstrap import audit as startup_audit, initializers
from check_sdk_pins import SDK_BINARIES
from encbound_inventory import get_marker

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(name,cmd,*,env=None,expected=0):
    p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env,timeout=300)
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
pins=json.loads((HERE/'pins.json').read_text())
assert subprocess.check_output(['git','-C',str(options.source),'rev-parse','HEAD'],text=True).strip()==pins['revision']
for n,h in pins['files'].items():assert digest(options.source/n)==h,n
math=BUILD/'math';math.mkdir(exist_ok=True)
import shutil
for n,h in pins['math'].items():
    src=PINNED/'sdk/tlibc'/n;assert digest(src)==h,n
    shutil.copyfile(src,math/Path(n).name)
run('libcxx-prepare',['python3',ROOT/'apps/libcxx/prepare.py'])
run('eh-headers',['python3',ROOT/'runtime/cxx_eh/prepare.py','--source',PINNED/'sdk/cpprt/linux','--out',BUILD/'abi-headers'])
run('cxx-headers',['python3',ROOT/'tools/prepare_cxx_headers.py','--sdk',SDK,'--out',BUILD/'headers'])
rows=[]
for opt in ('O2',):
 for serial in (False,):
  for profile,base in [('BASELINE','0x40000000'),('RADIX_ONLY','0x40000000'),
                       ('MAC27','0x40000000'),('MAC27','0x140000000')]:
    if options.profile and profile!=options.profile: continue
    if options.base and base!=options.base:continue
    key=f'{profile}-{base}-O2-O2'
    out=BUILD/key;out.mkdir(exist_ok=True);g=out/'generated'
    flags=['-m64','-'+opt,'-g','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections',
           '-fstack-protector-strong','-nostdinc','-I'+str(ROOT/'include'),'-I'+str(ROOT/'runtime'),
           '-I'+str(ROOT/'sdk'),'-I'+str(ROOT/'wrappers'),'-I'+str(HERE),'-I'+str(g),'-I'+str(SDK/'include'),
           '-I'+str(SDK/'include/tlibc'),'-isystem',str(PINNED/'common/inc/internal')]
    cppflags=flags+['-x','c++','-std=c++17','-fexceptions','-frtti','-nostdinc++','-I'+str(PREPARED/'headers'),'-I'+str(BUILD/'headers'),'-I'+str(SDK/'include/libcxx'),'-fno-common','-fno-builtin']
    cppflags+=['-D'+n+'=app_libcxx_'+n for n in ('memchr','wmemcpy','wmemmove','wmemset','wmemchr','wmemcmp','wcslen')]
    cppflags+=['-D'+n+'=sgxfs_'+n for n in ('floorl','floor','ceil')]
    interface=HERE/'interface.json'
    run(key+'-generate',['python3',ROOT/'tools/modified_bridge.py','--edl',HERE/'Enclave.edl',
       '--interface',interface,'--generator',ROOT/'build/edger8r/sgx_edger8r','--out-dir',g,
       '--profile',profile,'--cxx-eh','--search-path',options.source,'--search-path',options.source/'Enclave','--search-path',SDK/'include','--cc','gcc','--layout-cc','clang-21',
       *['--cflag='+f for f in flags]])
    # Actual definitions only, including ODR callbacks and cross-unit methods.
    definitions=set()
    app_sources={'enclave':options.source/'Enclave/Enclave.cpp','sealing':options.source/'Enclave/Sealing/Sealing.cpp','filesystem':options.source/'utils/filesystem.cpp'}
    for n,src in app_sources.items():
        ir=out/(n+'.frontend.ll')
        run(key+'-'+n+'-frontend',['clang-21',*cppflags,'-S','-emit-llvm',src,'-o',ir])
        obj=out/(n+'.frontend.o')
        run(key+'-'+n+'-inventory',['clang-21','-c',ir,'-o',obj])
        definitions |= names(obj,'--defined-only')
    library_env=dict(os.environ,ENCBOUND_CXX_EH='1',ENCBOUND_CXX_EH_ENTRIES=str(g/'eh-entries.txt'))
    extra=[*['--caller='+str(src) for src in app_sources.values()],*['--caller-flag='+f for f in ['-I'+str(g),*['-D'+n+'=sgxfs_'+n for n in ('floorl','floor','ceil')]]]]
    run(key+'-libcxx',[ROOT/'tools/with-integration-defaults.sh','env','ENCBOUND_CODEGEN_OPT=-O2',
        'python3',ROOT/'apps/libcxx/build.py','--profile',profile,'--frontend',opt,'--out-dir',out/'libcxx',*extra],env=library_env)
    librecord=json.loads((out/'libcxx/build.json').read_text())
    library=list(map(Path,librecord['objects']))
    definitions.update(Path(librecord['admitted']).read_text().split())
    mathflags=flags+['-std=c99','-D_TLIBC_GNU_','-fno-common','-fno-builtin','-I'+str(math),'-I'+str(PINNED/'common/inc/tlibc')]
    mathflags+=['-D'+n+'=sgxfs_'+n for n in ('floorl','floor','ceil')]
    for n in ('s_floorl','s_floor','s_ceil'):
        app_sources[n]=math/(n+'.c')
        obj=out/(n+'.frontend.o')
        run(key+'-'+n+'-inventory',['clang-21',*mathflags,'-c',app_sources[n],'-o',obj])
        definitions |= names(obj,'--defined-only')
    admitted=out/'admitted.txt';admitted.write_text('\n'.join(sorted(definitions))+'\n'+(g/'admitted-ocalls.txt').read_text()+('sgx_seal_data = encbound_sgx_seal_data\nsgx_unseal_data = encbound_sgx_unseal_data\n' if profile!='BASELINE' else ''))
    env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CXX_LIFECYCLE='1',ENCBOUND_CXX_EH='1',ENCBOUND_CXX_EH_ENTRIES=str(g/'eh-entries.txt'))
    app=[]
    for n,src in app_sources.items():
        obj=out/(n+'.o')
        run(key+'-'+n,['/bin/sh',ROOT/'tools/with-integration-defaults.sh','env','ENCBOUND_CXX_LIFECYCLE=1','ENCBOUND_CODEGEN_OPT=-O2',
            ROOT/'tools/encbound-cc.sh',src,obj,*(mathflags if n.startswith('s_') else cppflags)],env=env)
        placed=out/(n+'.placed.o')
        run(key+'-'+n+'-place',['python3',ROOT/'tools/mark_app_globals.py',obj,placed])
        placed.replace(obj);Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
        app.append(obj)
    app+=library
    sources={'Enclave_t':g/'Enclave_t.c','cxx_allocations':ROOT/'runtime/cxx_allocations.c','cxx_services':ROOT/'runtime/cxx_services.c'}
    defines=['-DENCBOUND_CXX_BASELINE'] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
    if profile=='MAC27':defines+=['-DENCBOUND_MAC27']
    if profile!='BASELINE':
        sources={'early_bootstrap':ROOT/'sdk/early_bootstrap.c','sdk_adapters':ROOT/'wrappers/sdk_adapters.c',**sources,
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
    archive=out/'application.a';run(key+'-archive',['ar','rcs',archive,*app[1:]])
    image=out/'enclave.so';linkmap=out/'enclave.map';libs=SDK/'lib64'
    cmd=['gcc',*trusted,app[0],'-Wl,--whole-archive',archive,'-Wl,--no-whole-archive','-o',image,'-Wl,-z,relro,-z,now,-z,noexecstack',
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
    if profile=='BASELINE':allowed|={'__cxa_atexit','__dso_handle','__cxa_guard_acquire','__cxa_guard_release','sgx_seal_data','sgx_unseal_data'}
    units=[]
    if profile=='BASELINE':allowed|=names(tcxx,'--defined-only')|names(SDK/'lib64/libsgx_tstdc.a','--defined-only')|{'abort','_Unwind_Resume'}
    else:allowed|={'_Unwind_Resume'}
    for obj in app:
        assert names(obj,'--undefined-only')<=allowed,names(obj,'--undefined-only')-allowed
        assert get_marker(obj)==(None if profile=='BASELINE' else profile)
        unit=json.loads(obj.with_suffix('.integration.json').read_text())
        enabled=('CALLBACKS','AGGREGATE_ABI','CXX_ALLOCATIONS','ATOMICS','VIRTUALS','VARIADICS','PROTECTED_GLOBALS','CXX_LIFECYCLE','VLA','CXX_EH')
        for setting in enabled: assert unit['settings']['ENCBOUND_'+setting]=='1',(obj,setting)
        for setting,value in dict(INTEGRATION_PRESET='all-compat-v1',CODEGEN_OPT='-O2',CHECK_REUSE='off',LOCAL_PROOFS='0',FAST_PATHS='off').items():
            assert unit['settings']['ENCBOUND_'+setting]==value,(obj,setting)
        for src,h in unit['inputs'].items():
            assert Path(src).resolve().is_relative_to(ROOT),src
            assert digest(Path(src))==h,src
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
    run(key+'-host',['gcc','-g','-O2','-I'+str(g),'-I'+str(SDK/'include'),HERE/'host.c',g/'Enclave_u.c',
        '-o',host,'-L'+str(libs),'-Wl,-rpath-link,'+str(libs),'-lsgx_urts_sim','-lpthread'])
    runenv=dict(os.environ,LD_LIBRARY_PATH=str(libs),ENCBOUND_TEST_BASE=base)
    p=run(key+'-run',[host,signed],env=runenv)
    assert 'SGX-FS SDK SIM PASS' in p.stdout
    rows.append(dict(mode='SDK SIM',profile=profile,base=base,frontend=opt,serial_guards=serial,
        image_sha256=digest(signed),units=units,archives={str(p):digest(p) for p in archives},
        initializers=(initializers(signed) if 'INIT_ARRAY' in subprocess.check_output(['readelf','-dW',str(signed)],text=True) else []),result='pass',link_command=list(map(str,cmd)),
        application_objects=list(map(str,app)),trusted_objects={str(p):digest(p) for p in trusted},
        loaded_image=str(signed),normal_ecalls=int(p.stdout.split('PASS: ')[1].split()[0]),codegen='O2',libcxx=True,trusted_units=trusted_units,
        host_sha256=digest(host),loaded_permissions='pass'))
    print(key,'PASS',flush=True)
(BUILD/('results-'+(options.profile or 'all')+'-'+(options.base or 'all')+'.json')).write_text(json.dumps(rows,indent=2)+'\n')
print('SGX-FS SDK SIM MATRIX PASS',len(rows))
