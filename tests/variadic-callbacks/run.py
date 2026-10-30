#!/usr/bin/env python3
"""Explicit indirect variadic ABI: native oracle/real checks and SDK SIM.

SDK link/sign/metadata recipes and native platform reuse tests/errno. Nothing
here establishes SGX hardware isolation, CFI or a complete SQLite integration.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
parser = argparse.ArgumentParser(description=__doc__)
selection = parser.add_mutually_exclusive_group()
selection.add_argument('--native-only', action='store_true')
selection.add_argument('--sim-only', action='store_true')
parser.add_argument('--build', type=Path, default=ROOT/'build/integration/variadic-callbacks')
args = parser.parse_args()
BUILD = args.build.resolve(); BUILD.mkdir(parents=True, exist_ok=True)
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PINNED = Path(os.environ.get('PINNED_SRC', str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from audit_app_variadics import audit as variadic_audit, records

record = dict(scope='native modeled platform with real runtime and Intel SGX SDK SIM; no hardware/CFI/performance',
              commands=[], rows=[])
sources = [HERE/'table.c', HERE/'calls.c', ROOT/'tests/pass/variadics_readers.c']
runtime = [ROOT/f'runtime/{n}.c' for n in ('runtime','siphash','capability','allocations','allocator','adapters')]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save():
    (BUILD/'results.json').write_text(json.dumps(record, indent=2)+'\n')


def run(name, command, *, env=None, expected=0):
    command = list(map(str, command))
    result = subprocess.run(command, text=True, capture_output=True, env=env, timeout=180)
    log = BUILD/(name+'.log'); log.write_text(result.stdout+result.stderr)
    record['commands'].append(dict(command=command, returncode=result.returncode,
                                   log=str(log), log_sha256=digest(log)))
    save()
    if expected is not None:
        assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
    return result


def application(key, out, profile, optimization, flags):
    # Obtain the inventory from the actual configured source definitions.
    definitions = set()
    for source in sources:
        probe = out/(source.stem+'.probe.ll')
        run(key+'-'+source.stem+'-probe', ['clang-21', '-S', '-emit-llvm', *flags, source, '-o', probe])
        definitions.update(re.findall(r'^define .*?@([\w.$]+)\(', probe.read_text(), re.M))
    admitted = out/'admitted.txt'; admitted.write_text('\n'.join(sorted(definitions))+'\n')
    app = []
    for source in sources:
        obj = out/(source.stem+'.o')
        env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted))
        run(key+'-'+source.stem, [ROOT/'tools/with-integration-defaults.sh', 'env',
            'ENCBOUND_CODEGEN_OPT=-'+optimization, ROOT/'tools/encbound-cc.sh', source, obj, *flags], env=env)
        placed = obj.with_suffix('.placed.o')
        run(key+'-'+source.stem+'-place', ['python3', ROOT/'tools/mark_app_globals.py', obj, placed])
        placed.replace(obj)
        Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
        checked = obj.with_suffix('.checked.ll').read_text()
        assert not re.search(r'^(define|declare) .*\.\.\.', checked, re.M)
        assert not re.search(r'@llvm\.va_(start|copy|end)', checked)
        assert records(obj)
        app.append(obj)
    assert any(line.startswith('I ') for line in records(app[1]))
    assert any(line.startswith('A ') for line in records(app[0]))
    return app


def denied(name, needle, image, app, trusted):
    try:
        variadic_audit(image, app, trusted)
    except ValueError as error:
        assert needle in str(error), (name, str(error))
        record['rows'].append(dict(mode='closure rejection control', case=name, result='pass', diagnostic=str(error)))
    else:
        raise AssertionError(name+' was admitted')


run('pass', ['make', '-C', ROOT/'pass'])
if not args.sim_only:
    target='target triple = "x86_64-pc-linux-gnu"\ntarget datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n'
    negatives = [
        ('address-disabled','define i64 @f(i32 %n, ...) { ret i64 0 }\n@p=global ptr @f\n',
         'variadic function address requires callbacks', False, False),
        ('indirect-disabled','define i64 @f(ptr %p) { %r=call i64 (i32,...) %p(i32 0,i64 1)\nret i64 %r }',
         'indirect variadic call requires callbacks', False, False),
        ('unowned-address','declare i64 @native(i32,...)\n@p=global ptr @native',
         'unowned variadic declaration', True, False),
        ('wide-int','define i64 @f(ptr %p) { %r=call i64 (i32,...) %p(i32 0,i128 1)\nret i64 %r }',
         'variadic argument type', True, False),
        ('long-double','define i64 @f(ptr %p,x86_fp80 %x) { %r=call i64 (i32,...) %p(i32 0,x86_fp80 %x)\nret i64 %r }',
         'variadic argument type', True, False),
        ('vector','define i64 @f(ptr %p,<2 x double> %x) { %r=call i64 (i32,...) %p(i32 0,<2 x double> %x)\nret i64 %r }',
         'variadic argument type', True, False),
        ('byval','define i64 @f(ptr %p,ptr %x) { %r=call i64 (i32,...) %p(i32 0,ptr byval(i64) %x)\nret i64 %r }',
         'variadic implicit memory ABI', True, False),
        ('inreg','define i64 @f(ptr %p) { %r=call i64 (i32,...) %p(i32 inreg 0,i64 1)\nret i64 %r }',
         'variadic parameter ABI attribute', True, False),
        ('calling-convention','define i64 @f(ptr %p) { %r=call x86_stdcallcc i64 (i32,...) %p(i32 0,i64 1)\nret i64 %r }',
         'variadic calling convention/result', True, False),
        ('operand-bundle','define i64 @f(ptr %p) { %r=call i64 (i32,...) %p(i32 0,i64 1) [ "deopt"(i32 1) ]\nret i64 %r }',
         'variadic call/ownership/prototype', True, False),
        ('variadic-alias','define i64 @f(i32 %n, ...) { ret i64 0 }\n@a=alias i64(i32,...),ptr @f',
         'unsupported variadic function alias', True, False),
        ('invoke-without-EH','declare i32 @personality()\ndefine i64 @f(ptr %p) personality ptr @personality {\n'
         ' %r=invoke i64 (i32,...) %p(i32 0,i64 1) to label %ok unwind label %error\n'
         'ok: ret i64 %r\nerror: %e=landingpad {ptr,i32} cleanup\nresume {ptr,i32} %e\n}',
         'variadic call/ownership/prototype', True, False),
        ('native-call-verifier','define i64 @f(ptr %p) { %r=call i64 (i32,...) %p(i32 0,i64 1)\nret i64 %r }',
         'native variadic call survived', True, True),
    ]
    for profile in ('BASELINE','RADIX_ONLY','MAC27'):
        for name, body, needle, callbacks, verify in negatives:
            if verify and profile=='BASELINE': continue
            key='admission-'+profile+'-'+name
            path=BUILD/(key+'.ll'); path.write_text(target+body+'\n')
            run(key+'-input', ['opt-21','-passes=verify','-disable-output',path])
            pipeline='encbound-verify' if verify else 'encbound-variadic-baseline'
            bad=run(key, ['opt-21','-load-pass-plugin='+str(ROOT/'build/pass/encbound_pass.so'),
                '-encbound-profile='+profile,'-encbound-variadics','-encbound-callbacks='+str(int(callbacks)),
                '-passes='+pipeline,'-disable-output',path], expected=None)
            assert bad.returncode and needle in bad.stderr, (key,bad.stderr)
            record['rows'].append(dict(mode='compiler/verifier rejection',profile=profile,case=name,result='pass',diagnostic=needle))
        # The existing bounded EH mode also uses LLVM's indirect InvokeInst
        # path. Check both successor edges and the result survive packing.
        path=BUILD/('invoke-enabled-'+profile+'.ll')
        path.write_text(target+next(body for name,body,*_ in negatives if name=='invoke-without-EH')+'\n')
        output=path.with_suffix('.normalized.ll')
        run('invoke-enabled-'+profile,['opt-21','-load-pass-plugin='+str(ROOT/'build/pass/encbound_pass.so'),
            '-encbound-profile='+profile,'-encbound-variadics','-encbound-callbacks','-encbound-cxx-eh',
            '-passes=encbound-variadic-baseline,verify','-S',path,'-o',output])
        checked=output.read_text()
        assert re.search(r'invoke i64 %p\(i32 0, ptr %encbound.va.initial\)\s+to label %ok unwind label %error',checked)
        assert 'ret i64 %r' in checked and 'resume { ptr, i32 } %e' in checked
        record['rows'].append(dict(mode='EH ABI-stage structural probe',profile=profile,
            case='indirect-invoke-successors',result='pass',execution=False))
    for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
        for optimization, base in [('O0', '0x40000000'), ('O2', '0x140000000')]:
            key='native-'+profile+'-'+optimization
            out=BUILD/key; out.mkdir(exist_ok=True)
            flags=['-'+optimization, '-g', '-fpie', '-fvisibility=hidden', '-fno-common', '-fno-builtin',
                   '-ffunction-sections','-fdata-sections', '-I'+str(ROOT/'include')]
            app=application(key, out, profile, optimization, flags)
            trusted=[]
            for source in sources:
                obj=out/('oracle-'+source.stem+'.o')
                run(key+'-oracle-'+source.stem, ['clang-21', '-O2', '-DORACLE', '-c', source, '-o', obj])
                trusted.append(obj)
            defines=[] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
            if profile=='MAC27': defines+=['-DENCBOUND_MAC27']
            for source in [HERE/'native.c', *runtime]:
                obj=out/(source.stem+'.o')
                run(key+'-'+source.stem, ['clang-21', *flags, *defines, '-c', source, '-o', obj])
                trusted.append(obj)
            image=out/'test'; linkmap=out/'test.map'
            run(key+'-link', ['clang-21', *app, *trusted, '-pie', '-Wl,-Ttext-segment='+base,
                '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'), '-Wl,-Map,'+str(linkmap), '-o', image])
            linked=[Path(line[5:]) for line in linkmap.read_text().splitlines()
                    if line.startswith('LOAD ') and line.endswith('.o')]
            all_trusted=[p for p in linked if p.resolve() not in {obj.resolve() for obj in app}]
            ownership_audit(image, app, all_trusted, linkmap)
            result=run(key+'-run', [image])
            assert 'INDIRECT VARIADIC NATIVE PASS cases=20 bits=1023' in result.stdout
            record['rows'].append(dict(mode='native real runtime / modeled ELF platform', profile=profile,
                optimization=optimization, base=base, output=result.stdout.strip(), result='pass',
                image_sha256=digest(image), linkmap_sha256=digest(linkmap)))
            print(key, result.stdout.strip(), flush=True)
            if profile=='MAC27' and optimization=='O2':
                denied('missing-callee', 'missing or duplicate application definition', image, app[:-1], all_trusted)
                denied('trusted-callee', 'private callback ABI in trusted', image, app[:-1], all_trusted+[app[-1]])
                manifest=app[0].with_suffix('.integration.json'); original=manifest.read_bytes()
                for setting, value, needle in [('ENCBOUND_VARIADICS','0','inconsistent application ABI'),
                                              ('ENCBOUND_CALLBACKS','0','without callbacks'),
                                              ('ENCBOUND_PROFILE','RADIX_ONLY','profile/domain mismatch')]:
                    changed=json.loads(original); changed['settings'][setting]=value
                    manifest.write_text(json.dumps(changed))
                    try: denied(setting, needle, image, app, all_trusted)
                    finally: manifest.write_bytes(original)
                checked=app[0].with_suffix('.checked.ll'); original=checked.read_bytes()
                checked.write_bytes(original+b'\n; changed\n')
                try: denied('changed-IR', 'retained IR identity', image, app, all_trusted)
                finally: checked.write_bytes(original)
                # Incompatible/native definitions cannot satisfy the private names.
                native_callee=out/'native-callee.o'
                run(key+'-native-callee', ['clang-21','-O2','-c',sources[-1],'-o',native_callee])
                for case, callee in [('native-callee', native_callee),
                    ('wrong-profile', BUILD/'native-RADIX_ONLY-O2/variadics_readers.o')]:
                    bad=run(key+'-'+case+'-link', ['clang-21', *app[:-1], callee, *trusted,
                        '-pie', '-Wl,-Ttext-segment='+base, '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'),
                        '-o', out/(case+'-bad')], expected=None)
                    assert bad.returncode and '__encbound_va_' in bad.stderr and 'undefined reference' in bad.stderr, bad.stderr
                    record['rows'].append(dict(mode='incompatible link rejection',case=case,result='pass'))

if not args.native_only:
    run('generator', ['make', '-C', ROOT/'tools/edger8r'])
    run('sdk-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', PINNED])
    for profile, base in [('BASELINE','0x40000000'), ('RADIX_ONLY','0x40000000'),
                          ('MAC27','0x40000000'), ('MAC27','0x140000000')]:
        key='sim-'+profile+'-'+base
        out=BUILD/key; out.mkdir(exist_ok=True)
        flags=['-m64','-O2','-g','-fvisibility=hidden','-fpie','-fno-common','-fno-builtin',
               '-ffunction-sections','-fdata-sections','-fstack-protector-strong','-nostdinc',
               *['-I'+str(p) for p in (ROOT/'include', ROOT/'runtime', ROOT/'sdk', SDK/'include', SDK/'include/tlibc')],
               '-isystem',str(PINNED/'common/inc/internal')]
        interface=out/'interface.json'
        interface.write_text(json.dumps({'records':{}, 'sdk_only_imports':
            json.loads((ROOT/'apps/libc-format/boundary-interface.json').read_text())['sdk_only_imports']})+'\n')
        generated=out/'generated'
        run(key+'-generate', ['python3',ROOT/'tools/modified_bridge.py','--edl',HERE/'probe.edl',
            '--interface',interface,'--generator',ROOT/'build/edger8r/sgx_edger8r','--profile',profile,
            '--out-dir',generated,'--search-path',SDK/'include', *['--cflag='+f for f in flags]])
        flags+=['-I'+str(generated)]
        app=application(key, out, profile, 'O2', flags)
        defines=[] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
        if profile=='MAC27': defines+=['-DENCBOUND_MAC27']
        trusted_sources=[generated/'probe_t.c', HERE/'trusted.c']
        if profile!='BASELINE':
            trusted_sources += [ROOT/'sdk/boundary_support.c', ROOT/'sdk/platform_layout.c', *runtime]
        trusted=[]
        for source in trusted_sources:
            obj=out/(source.stem+'.o')
            run(key+'-'+source.stem, ['gcc',*flags,*defines,'-c',source,'-o',obj]); trusted.append(obj)
        image=out/'enclave.so'; linkmap=out/'enclave.map'; libraries=SDK/'lib64'
        run(key+'-link', ['gcc',*app,*trusted,'-o',image,
            '-Wl,-z,relro,-z,now,-z,noexecstack','-Wl,--no-undefined','-nostdlib','-nodefaultlibs','-nostartfiles',
            '-L'+str(libraries),'-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive',
            '-Wl,--start-group','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group',
            '-Wl,-Bstatic','-Wl,-Bsymbolic','-Wl,-pie,-eenclave_entry','-Wl,--export-dynamic',
            '-Wl,--defsym,__ImageBase=0','-Wl,--gc-sections','-Wl,-Map,'+str(linkmap),
            '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),'-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')])
        ownership_audit(image, app, trusted, linkmap)
        run(key+'-link-pins', ['python3',ROOT/'tools/check_sdk_pins.py','--sdk',SDK,
                              '--pinned',PINNED,'--link-map',linkmap])
        private_key=out/'test-key.pem'
        if not private_key.exists(): run(key+'-key', ['openssl','genrsa','-out',private_key,'-3','3072'])
        sizing=out/'sizing.xml'; signed=out/'enclave.signed.so'
        run(key+'-sizing-config', ['python3',ROOT/'tools/sgx_metadata.py','render-config',
            '--template',ROOT/'sdk/enclave.config.tmpl.xml','--base',base,'--size','0x40000000','--out',sizing])
        run(key+'-sizing-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,
                               '-enclave',image,'-out',out/'sizing.so','-config',sizing])
        extent=run(key+'-extent', ['python3',ROOT/'tools/sgx_metadata.py','required','--signed',out/'sizing.so']).stdout.strip()
        final=out/'final.xml'
        run(key+'-final-config', ['python3',ROOT/'tools/sgx_metadata.py','render-config',
            '--template',ROOT/'sdk/enclave.config.tmpl.xml','--base',base,'--size',extent,'--out',final])
        run(key+'-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,'-enclave',image,'-out',signed,'-config',final])
        run(key+'-metadata', ['python3',ROOT/'tools/sgx_metadata.py','verify','--signed',signed,'--base',base,'--size',extent])
        host=out/'host'
        run(key+'-host', ['gcc','-g','-O2','-I'+str(generated),'-I'+str(SDK/'include'),
            HERE/'host.c',generated/'probe_u.c','-o',host,'-L'+str(libraries),
            '-Wl,-rpath-link,'+str(libraries),'-lsgx_urts_sim','-lpthread'])
        env=dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libraries),ENCBOUND_TEST_BASE=base)
        result=run(key+'-run', [host,signed], env=env)
        assert result.stdout.strip()=='INDIRECT VARIADIC SDK SIM PASS cases=20 bits=1023', result.stdout
        record['rows'].append(dict(mode='Intel SGX SDK SIM',profile=profile,base=base,result='pass',cases=20,
            image_sha256=digest(signed),host_sha256=digest(host),linkmap_sha256=digest(linkmap)))
        print(key, result.stdout.strip(), flush=True)
        controls=[1] if profile=='BASELINE' else list(range(1,6 if profile=='MAC27' else 5))
        for case in controls:
            result=run(key+'-control-'+str(case), [host,signed,str(case)], env=env,
                       expected=0 if profile=='BASELINE' else -4)
            if profile=='BASELINE':
                record['rows'].append(dict(mode='SDK SIM matched private write',profile=profile,result='succeeds'))
            else:
                traced=run(key+'-attribute-'+str(case), ['gdb','-q','-batch','-ex','set pagination off',
                    '-ex','add-symbol-file '+str(image)+' -o '+base,'-ex','run',
                    '-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt', '--args',host,signed,str(case)], env=env)
                trace=traced.stdout+traced.stderr
                code=4 if case==4 else 5 if case==5 else 3
                assert 'SIGILL' in trace and 'ABORT_CODE '+str(code)+'\n' in trace and 'encbound_abort' in trace and 'va_bad' in trace, trace
                record['rows'].append(dict(mode='SDK SIM attributed protection control',profile=profile,base=base,
                    case=case,abort_code=code,origin='va_bad via indirect_case',result='pass'))

paths=[*HERE.glob('*.[ch]'),Path(__file__),ROOT/'tests/pass/variadics_readers.c',ROOT/'tests/pass/variadics_fixture.h',
       ROOT/'pass/encbound_variadics.h',ROOT/'pass/encbound_x86_variadics.h',ROOT/'pass/upstream/ExpandVariadics.cpp',
       ROOT/'tools/audit_app_variadics.py',ROOT/'tools/audit_app_globals.py',ROOT/'build/pass/encbound_pass.so']
record['sources']={str(p):digest(p) for p in paths}
save()
print('INDIRECT VARIADIC ACCEPTANCE PASS:',len(record['rows']),'recorded rows')
