#!/usr/bin/env python3
"""Real emitted host/enclave bridges, instrumented app errno and SDK SIM rows.

The native platform is a model over its linked ELF, not hardware isolation.
SDK link/sign/metadata and loaded-page recipes reuse tests/early-bootstrap.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
parser = argparse.ArgumentParser(description=__doc__)
selection = parser.add_mutually_exclusive_group()
selection.add_argument('--native-only', action='store_true')
selection.add_argument('--sim-only', action='store_true')
parser.add_argument('--build', type=Path, default=ROOT/'build/integration/errno')
args = parser.parse_args()
BUILD = args.build.resolve(); BUILD.mkdir(parents=True, exist_ok=True)
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PINNED = Path(os.environ.get('PINNED_SRC', str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from audit_app_errno import audit as errno_audit
from encbound_inventory import get_marker

record = dict(scope='native real runtime and Intel SGX SDK SIM; no hardware/performance claim', commands=[], rows=[])


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save():
    (BUILD/'results.json').write_text(json.dumps(record, indent=2)+'\n')


def run(name, command, *, env=None, expected=0):
    command = list(map(str, command))
    result = subprocess.run(command, text=True, capture_output=True, env=env, timeout=120)
    log = BUILD/(name+'.log'); log.write_text(result.stdout+result.stderr)
    record['commands'].append(dict(command=command, returncode=result.returncode,
                                   log=str(log), log_sha256=digest(log)))
    save()
    if expected is not None:
        assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
    return result


def app_object(key, source, out, profile, optimization, flags, admitted):
    obj = out/(source.stem+'.o')
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted))
    run(key+'-'+source.stem, [ROOT/'tools/with-integration-defaults.sh', 'env',
        'ENCBOUND_CODEGEN_OPT=-'+optimization, ROOT/'tools/encbound-cc.sh', source, obj,
        '-'+optimization, '-g', '-fpie', '-fvisibility=hidden', '-fno-common', '-fno-builtin',
        *(['-std=c++17', '-fno-exceptions', '-fno-rtti'] if source.suffix=='.cpp' else []),
        '-ffunction-sections', '-fdata-sections', *flags], env=env)
    placed = obj.with_suffix('.placed.o')
    run(key+'-'+source.stem+'-place', ['python3', ROOT/'tools/mark_app_globals.py', obj, placed])
    placed.replace(obj)
    Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
    unit = json.loads(obj.with_suffix('.integration.json').read_text())
    assert unit['settings']['ENCBOUND_APP_ERRNO']=='1' and unit['settings']['ENCBOUND_PROTECTED_GLOBALS']=='1'
    assert get_marker(obj) == (None if profile=='BASELINE' else profile)
    for path, expected in unit['inputs'].items(): assert digest(path)==expected
    return obj


def generate(key, out, profile, flags, *, sdk_sim=False):
    source = HERE/'probe.edl'
    metadata = {'records':{}, 'sdk_only_imports':{}}
    if sdk_sim:
        # The protected runtime's SDK allocator uses SDK event OCALLs. Retain
        # the pinned SDK import and its SDK ownership, as in existing recipes.
        source = out/'probe.edl'
        source.write_text((HERE/'probe.edl').read_text().replace('enclave {',
            'enclave {\n    from "sgx_tstdc.edl" import *;', 1))
        metadata['sdk_only_imports'] = json.loads((ROOT/'apps/libc-format/boundary-interface.json').read_text())['sdk_only_imports']
    interface = out/'interface.json'; interface.write_text(json.dumps(metadata)+'\n')
    generated = out/'generated'
    run(key+'-generate', ['python3', ROOT/'tools/modified_bridge.py', '--edl', source,
        '--interface', interface, '--generator', ROOT/'build/edger8r/sgx_edger8r',
        '--profile', profile, '--out-dir', generated, '--search-path', SDK/'include', *['--cflag='+f for f in flags]])
    manifest = json.loads((generated/'boundary-manifest.json').read_text())
    assert manifest['propagate_errno_ocalls']==['errno_exchange','errno_void','errno_naked']
    assert set(manifest['required_application_symbols'])=={'__encbound_app_errno_location','__encbound_app_errno_store'}
    assert str(ROOT/'include/encbound_app_errno.h') in manifest['inputs']
    admitted = out/'admitted.txt'
    # All entries below have actual application definitions in the linked units.
    admitted.write_text('errno_case\nerrno_read\nerrno_write\nerrno_pointer\nerrno_access\n'
        'errno_dependency_read\nerrno_dependency_write\n__encbound_app_errno_location\n__encbound_app_errno_store\n'+
        (generated/'admitted-ocalls.txt').read_text())
    return generated, admitted


def audit_denied(name, expected, image, app, trusted):
    try: errno_audit(image, app, trusted)
    except ValueError as error:
        assert expected in str(error), (name, str(error))
        record['rows'].append(dict(mode='ownership audit negative control', case=name, result='pass', diagnostic=str(error)))
    else: raise AssertionError(name+' was admitted')


run('pass', ['make', '-C', ROOT/'pass'])
run('generator', ['make', '-C', ROOT/'tools/edger8r'])
if not args.sim_only:
    for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
        for optimization, base in [('O0', '0x40000000'), ('O2', '0x140000000')]:
            key='native-'+profile+'-'+optimization
            out=BUILD/key; out.mkdir(exist_ok=True)
            flags=['-I'+str(p) for p in (HERE/'native_include', ROOT/'include', ROOT/'sdk', ROOT/'runtime', SDK/'include', HERE)]
            generated, admitted=generate(key, out, profile, flags)
            flags+=['-I'+str(generated)]
            app=[app_object(key, source, out, profile, optimization, flags, admitted)
                 for source in (HERE/'application.c', HERE/'dependency.cpp', ROOT/'libc/errno.c')]
            defines=[] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
            if profile=='MAC27': defines+=['-DENCBOUND_MAC27']
            trusted=[]
            sources={'native':HERE/'native.c', 'native_host':HERE/'native_host.c',
                     'boundary_support':ROOT/'sdk/boundary_support.c',
                     **{n:ROOT/f'runtime/{n}.c' for n in ('runtime','siphash','capability','allocations','allocator','adapters')}}
            for name, source in sources.items():
                obj=out/(name+'.o')
                extra=['-I'+str(HERE/'native_include')] if name=='native' else []
                run(key+'-'+name, ['clang-21', '-'+optimization, '-g', '-fpie', *extra, *flags,
                                  *defines, '-c', source, '-o', obj])
                trusted.append(obj)
            image=out/'test'; linkmap=out/'test.map'
            command=['clang-21', *app, *trusted, '-pie', '-Wl,-Ttext-segment='+base,
                     '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'), '-Wl,-Map,'+str(linkmap), '-o', image]
            run(key+'-link', command)
            linked=[Path(line[5:]) for line in linkmap.read_text().splitlines()
                    if line.startswith('LOAD ') and line.endswith('.o')]
            all_trusted=[p for p in linked if p.resolve() not in {obj.resolve() for obj in app}]
            ownership_audit(image, app, all_trusted, linkmap)
            result=run(key+'-run', [image])
            assert 'ERRNO NATIVE PASS cases=60' in result.stdout
            record['rows'].append(dict(mode='native real runtime / modeled platform', profile=profile,
                optimization=optimization, base=base, output=result.stdout.strip(), result='pass',
                image_sha256=digest(image), linkmap_sha256=digest(linkmap)))
            print(key, result.stdout.strip(), flush=True)
            if profile=='MAC27' and optimization=='O2':
                audit_denied('missing-provider', 'missing or duplicate', image, app[:-1], all_trusted)
                audit_denied('duplicate-provider', 'missing or duplicate', image, app+[app[-1]], all_trusted)
                audit_denied('trusted-provider', 'defined in trusted', image, app[:-1], all_trusted+[app[-1]])
                audit_denied('trusted-getter', 'trusted code requests application errno pointer',
                             image, app, all_trusted+[app[0]])
                raw=out/'raw-errno.o'
                run(key+'-raw-errno', ['objcopy', '--redefine-sym',
                    '__encbound_app_errno_location=__errno_location', app[0], raw])
                audit_denied('raw-errno-caller', 'raw or separate errno symbol',
                             image, [raw, *app[1:]], all_trusted)
                bad=run(key+'-trusted-overlay', ['clang-21', '-I'+str(ROOT/'include/encbound_app_libc'),
                    *flags, *defines, '-c', generated/'probe_t.c', '-o', out/'bad-trusted-overlay.o'],
                    expected=None)
                assert bad.returncode and 'Application errno headers must not be used for the trusted bridge' in bad.stderr, bad.stderr
                record['rows'].append(dict(mode='trusted compilation negative control',
                    case='application-overlay', result='pass'))
                for name, objects, expected in [('missing-provider', app[:-1], '__encbound_app_errno_store'),
                                                ('duplicate-provider', app+[app[-1]], 'multiple definition')]:
                    bad=run(key+'-'+name+'-link', ['clang-21', *objects, *trusted, '-pie',
                        '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'), '-o', out/(name+'-bad')], expected=None)
                    assert bad.returncode and expected in bad.stderr, bad.stderr
                    record['rows'].append(dict(mode='link negative control', case=name, result='pass'))

# SIM fixtures use actual SDK headers, libc and host transport. Application
# support objects are built separately through the same full integration preset.
if not args.native_only:
    run('sdk-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', PINNED])
    for profile, base in [('BASELINE','0x40000000'), ('RADIX_ONLY','0x40000000'),
                          ('MAC27','0x40000000'), ('MAC27','0x140000000')]:
        key='sim-'+profile+'-'+base
        out=BUILD/key; out.mkdir(exist_ok=True)
        flags=['-m64','-O2','-g','-fvisibility=hidden','-fpie','-ffunction-sections','-fdata-sections',
               '-fstack-protector-strong','-nostdinc',
               *['-I'+str(p) for p in (ROOT/'include', ROOT/'runtime', ROOT/'sdk', SDK/'include', SDK/'include/tlibc')],
               '-isystem',str(PINNED/'common/inc/internal')]
        generated, admitted=generate(key, out, profile, flags, sdk_sim=True)
        flags+=['-I'+str(generated)]
        app=[app_object(key, source, out, profile, 'O2', flags, admitted)
             for source in (HERE/'application.c', HERE/'dependency.cpp', ROOT/'libc/errno.c')]
        defines=[] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
        if profile=='MAC27': defines+=['-DENCBOUND_MAC27']
        sources={'probe_t':generated/'probe_t.c', 'trusted':HERE/'trusted.c'}
        if profile!='BASELINE':
            sources.update(boundary_support=ROOT/'sdk/boundary_support.c', platform_layout=ROOT/'sdk/platform_layout.c')
            sources.update({n:ROOT/f'runtime/{n}.c' for n in ('runtime','siphash','capability','allocations','allocator','adapters')})
        trusted=[]
        for name, source in sources.items():
            obj=out/(name+'.o')
            run(key+'-'+name, ['gcc', *flags, *defines, '-c', source, '-o', obj]); trusted.append(obj)
        image=out/'enclave.so'; linkmap=out/'enclave.map'; libraries=SDK/'lib64'
        run(key+'-link', ['gcc', *app, *trusted, '-o', image,
            '-Wl,-z,relro,-z,now,-z,noexecstack','-Wl,--no-undefined','-nostdlib','-nodefaultlibs','-nostartfiles',
            '-L'+str(libraries),'-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive',
            '-Wl,--start-group','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group',
            '-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry','-Wl,--export-dynamic',
            '-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),
            '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),'-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')])
        ownership_audit(image, app, trusted, linkmap)
        run(key+'-link-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK,
                              '--pinned', PINNED, '--link-map', linkmap])
        private_key=out/'test-key.pem'
        if not private_key.exists(): run(key+'-key', ['openssl','genrsa','-out',private_key,'-3','3072'])
        sizing=out/'sizing.xml'; signed=out/'enclave.signed.so'
        run(key+'-sizing-config', ['python3', ROOT/'tools/sgx_metadata.py','render-config',
            '--template',ROOT/'sdk/enclave.config.tmpl.xml','--base',base,'--size','0x40000000','--out',sizing])
        run(key+'-sizing-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,
                               '-enclave',image,'-out',out/'sizing.so','-config',sizing])
        extent=run(key+'-extent', ['python3', ROOT/'tools/sgx_metadata.py','required','--signed',out/'sizing.so']).stdout.strip()
        final=out/'final.xml'
        run(key+'-final-config', ['python3', ROOT/'tools/sgx_metadata.py','render-config',
            '--template',ROOT/'sdk/enclave.config.tmpl.xml','--base',base,'--size',extent,'--out',final])
        run(key+'-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,'-enclave',image,'-out',signed,'-config',final])
        run(key+'-metadata', ['python3', ROOT/'tools/sgx_metadata.py','verify','--signed',signed,'--base',base,'--size',extent])
        host=out/'host'
        run(key+'-host', ['gcc','-g','-O2','-I'+str(generated),'-I'+str(SDK/'include'),
            HERE/'host.c',HERE/'host_services.c',generated/'probe_u.c','-o',host,
            '-L'+str(libraries),'-Wl,-rpath-link,'+str(libraries),'-lsgx_urts_sim','-lpthread'])
        env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libraries),ENCBOUND_TEST_BASE=base)
        result=run(key+'-run', [host,signed], env=env)
        assert result.stdout.strip()=='ERRNO SDK SIM PASS cases=60', result.stdout
        record['rows'].append(dict(mode='Intel SGX SDK SIM', profile=profile, base=base,
            result='pass', cases=60, image_sha256=digest(signed), host_sha256=digest(host),
            linkmap_sha256=digest(linkmap), boundary_manifest_sha256=digest(generated/'boundary-manifest.json')))
        print(key, result.stdout.strip(), flush=True)
        for case in ('sdk-read','sdk-write'):
            result=run(key+'-'+case, [host,signed,case], env=env, expected=0 if profile=='BASELINE' else -4)
            record['rows'].append(dict(mode='SDK SIM private-state control',profile=profile,base=base,
                case=case,result='baseline access' if profile=='BASELINE' else 'SIGILL; debugger attribution below'))
            if profile!='BASELINE':
                traced=run(key+'-'+case+'-attribution', ['gdb','-q','-batch','-ex','set pagination off',
                    '-ex','add-symbol-file '+str(image)+' -o '+base,'-ex','run',
                    '-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt',
                    '--args',host,signed,case], env=env)
                trace=traced.stdout+traced.stderr
                assert 'SIGILL' in trace and 'ABORT_CODE 3\n' in trace and 'encbound_abort' in trace and 'errno_access' in trace, trace
                record['rows'].append(dict(mode='SDK SIM debugger attribution',profile=profile,base=base,
                    case=case,abort_code=3,origin='errno_access',result='pass'))

paths=[p for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
paths += [ROOT/p for p in ('libc/errno.c','include/encbound_app_errno.h','include/encbound_app_libc/errno.h',
    'tools/encbound-cc.sh','tools/record_integration_unit.py','tools/modified_bridge.py','tools/audit_app_errno.py',
    'tools/audit_app_globals.py','tools/edger8r/CodeGen.ml','tools/edger8r/EncboundAdmission.ml','config/integration.env',
    'build/pass/encbound_pass.so','build/edger8r/sgx_edger8r')]
record['sources']={str(p):digest(p) for p in paths}
save()
print('APPLICATION ERRNO ACCEPTANCE PASS:',len(record['rows']),'recorded rows')
