#!/usr/bin/env python3
"""Check Crust's selected body/dispatch with the terminal restore adaptation.

Builds application objects, not a complete enclave or protected libc++ closure.
Native execution tests only the terminal callback and its non-access contract.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHARED = ROOT/'apps/serial-mutex'
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--checkout', type=Path, default=ROOT/'build/paper-sources/crust-sworker')
parser.add_argument('--out-dir', type=Path, default=ROOT/'build/crust-selected/terminal-restore-v1/all-compat-v1')
args = parser.parse_args()
OUT = args.out_dir.resolve()
OUT.mkdir(parents=True, exist_ok=True)
(OUT/'results.json').unlink(missing_ok=True)
rows = []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(label, command, env=None, expected=0):
    command = list(map(str, command))
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=120)
    log = OUT/(label+'.log')
    log.write_text(result.stdout+result.stderr)
    rows.append(dict(label=label, command=command, returncode=result.returncode,
                     expected_returncode=expected, log=str(log), log_sha256=sha(log)))
    if result.returncode != expected:
        raise RuntimeError(f'{label}: {result.returncode}, expected {expected}\n{result.stdout}{result.stderr}')
    print(label, 'PASS', flush=True)
    return result.stdout+result.stderr


pins = json.loads((HERE/'pins.json').read_text())
source = OUT/'source'
source.mkdir(exist_ok=True)
for name, expected in pins['files'].items():
    content = subprocess.check_output(['git', '-C', str(args.checkout), 'show', pins['revision']+':'+name])
    assert hashlib.sha256(content).hexdigest() == expected, name
    (source/Path(name).name).write_bytes(content)

# Preserve the exact upstream body, buffer globals and dispatch initializer.
# Only unrelated umbrella includes are replaced and the units are split.
original = (source/'Enclave.cpp').read_text()
body = original[original.index('crust_status_t ecall_safe_store2('):].strip()
assert hashlib.sha256(body.encode()).hexdigest() == pins['selected_body_sha256']
globals_text = original[original.index('std::map<uint32_t, uint8_t *>'):original.index('/**')]
split = globals_text.index('std::map<ecall_store_type_t, ecall_store2_f>')
header = '#include <map>\n#include <stdlib.h>\n#include <string.h>\n#include "Parameter.h"\n#include "SafeLock.h"\n'
(source/'selected.cpp').write_text(header+
    'extern "C" crust_status_t ecall_safe_store2(ecall_store_type_t, const uint8_t *, size_t, size_t, size_t, uint32_t);\n'+
    globals_text[:split]+'extern std::map<ecall_store_type_t, ecall_store2_f> g_ecall_store2_func_m;\n'+body+'\n')
(source/'dispatch.cpp').write_text(header+'#include "restore_stub.h"\n'+globals_text[split:])
run('pass-build', ['make', '-C', ROOT/'pass'])
run('libcxx-input-verify', ['python3', ROOT/'apps/libcxx/verify.py'])

# Recollect real definitions from the verified library sources. Historical
# library objects are neither linked nor presented as a fresh library build.
lib_record_path = ROOT/'build/libcxx/MAC27/build.json'
lib_record = json.loads(lib_record_path.read_text())
flags = ['-I'+str(ROOT/'include/encbound_app_libc'), '-I'+str(ROOT/'include'), *lib_record['flags']]
caller_flags = ['-I'+str(source), '-I'+str(HERE), '-I'+str(SHARED)]
library_sources = [ROOT/'build/libcxx/src'/f'{unit}.cpp' for unit in lib_record['source_inventory']['units']]
library_sources += [ROOT/'apps/libcxx/wide_memory.cpp']
application_sources = [source/'selected.cpp', source/'dispatch.cpp', source/'SafeLock.cpp',
                       SHARED/'serial_mutex.cpp', HERE/'restore_stub.cpp']


def scoped_flags(unit):
    return ['-include', str(SHARED/'serial_mutex_redirect.h')] if unit.name == 'SafeLock.cpp' else []


definitions = set()
frontend = OUT/'frontend'
frontend.mkdir(exist_ok=True)
for unit in library_sources+application_sources:
    ir = frontend/(unit.stem+'.ll')
    run('frontend-'+unit.stem, ['clang++-21', *flags,
        *(caller_flags if unit in application_sources else []), *scoped_flags(unit),
        '-S', '-emit-llvm', unit, '-o', ir])
    definitions.update(re.findall(r'^define .*?@([^ (]+)\(', ir.read_text(), re.M))
    definitions.update(re.findall(r'^@([^ ]+) = .*?alias ', ir.read_text(), re.M))
assert 'ecall_restore_from_upgrade' in definitions
assert not {'sgx_thread_mutex_lock', 'sgx_thread_mutex_unlock'} & definitions
admitted = OUT/'admitted.txt'
admitted.write_text('\n'.join(sorted(definitions))+'\n')
missing = OUT/'admitted-without-restore.txt'
missing.write_text('\n'.join(sorted(definitions-{'ecall_restore_from_upgrade'}))+'\n')

for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    work = OUT/profile
    work.mkdir(exist_ok=True)
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted),
               ENCBOUND_CXX_EH='0', ENCBOUND_KEEP_GEP_FLAGS='0', ENCBOUND_POST_INSTCOMBINE='0')
    objects = []
    for unit in application_sources:
        obj = work/(unit.stem+'.o')
        obj.unlink(missing_ok=True)
        run('application-'+profile+'-'+unit.stem,
            [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
             unit, obj, *flags, *caller_flags, *scoped_flags(unit)], env)
        settings = json.loads(obj.with_suffix('.integration.json').read_text())['settings']
        assert settings['ENCBOUND_PROFILE'] == profile
        assert settings['ENCBOUND_INTEGRATION_PRESET'] == 'all-compat-v1'
        for feature in ('CALLBACKS', 'AGGREGATE_ABI', 'CXX_ALLOCATIONS', 'ATOMICS', 'VIRTUALS',
                        'VARIADICS', 'PROTECTED_GLOBALS', 'CXX_LIFECYCLE', 'VLA', 'APP_ERRNO'):
            assert settings['ENCBOUND_'+feature] == '1', (profile, feature)
        placed = work/(unit.stem+'.placed.o')
        run('placement-'+profile+'-'+unit.stem,
            [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/mark_appdata_sections.sh', obj, placed], env)
        objects.append(placed)
    selected_ir = (work/'selected.checked.ll').read_text()
    if profile != 'BASELINE':
        assert '@encbound_memcpy(' in selected_ir
        assert '@encbound_malloc(' in selected_ir
        assert '@encbound_memset(' in selected_ir
        # The hostile length must still reach the checked copy unchanged.
        parameters = re.search(r'define [^\n]*@ecall_safe_store2\(([^)]*)\)', selected_ir).group(1)
        partial_size = parameters.split(',')[3].split()[-1]
        assert re.search(r'@encbound_memcpy\([^\n]*i64(?: noundef)? '+re.escape(partial_size)+r'\)', selected_ir)
    stub_ir = (work/'restore_stub.checked.ll').read_text()
    assert '@encbound_cxx_fail(' in stub_ir
    assert not re.search(r'^\s*(?:ret |.*\b(?:load|store)\b)', stub_ir, re.M)

    # This partial link closes the callback address across application objects;
    # it does not resolve the runtime/library closure or constitute an enclave.
    combined = work/'selected-application.o'
    run('partial-link-'+profile, ['ld', '-r', '-o', combined, *objects])
    symbols = run('symbols-'+profile, ['llvm-nm-21', combined])
    assert re.search(r'\bT ecall_restore_from_upgrade$', symbols, re.M)
    assert not re.search(r'\bU ecall_restore_from_upgrade$', symbols, re.M)
    assert not re.search(r'sgx_thread_mutex_(?:lock|unlock)|id_restore_from_upgrade|Workload', symbols)

    # No redirect or application pass in trusted native test/service objects.
    services = work/'trusted-cxx-services.o'
    driver = work/'trusted-restore-driver.o'
    run('native-services-'+profile, ['clang-21', '-O2', '-MMD', '-MF', services.with_suffix('.d'),
        '-c', ROOT/'runtime/cxx_services.c', '-o', services])
    run('native-driver-'+profile, ['clang++-21', '-O2', '-fno-exceptions', '-fno-rtti',
        *caller_flags, '-MMD', '-MF', driver.with_suffix('.d'),
        '-c', HERE/'restore_stub_native.cpp', '-o', driver])
    binary = work/'native-restore'
    run('native-link-'+profile, ['clang++-21', work/'restore_stub.placed.o', services, driver, '-lm', '-o', binary])
    for case in ('null', 'unreadable', 'poisoned'):
        run('native-'+profile+'-'+case, [binary, case], expected=-signal.SIGABRT)

    if profile != 'BASELINE':
        rejected = work/'dispatch.missing-control.o'
        rejected.unlink(missing_ok=True)
        diagnostic = run('negative-missing-restore-'+profile,
            [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
             source/'dispatch.cpp', rejected, *flags, *caller_flags],
            dict(env, ENCBOUND_ADMITTED=str(missing)), expected=134)
        assert 'ecall_restore_from_upgrade' in diagnostic
        assert not rejected.exists()

dependencies = set(library_sources+application_sources+[lib_record_path, HERE/'pins.json',
    HERE/'restore_stub.h', HERE/'restore_stub_native.cpp', Path(__file__)])
for dep in OUT.rglob('*.d'):
    for name in shlex.split(dep.read_text().replace('\\\n', ' ').partition(':')[2]):
        path = Path(name).resolve()
        if path.is_file():
            dependencies.add(path)
record = dict(evidence_class='application object admission/partial link and native terminal-callback execution',
    pins=pins, adaptation='application-owned terminal restore callback; unchanged dispatch initializer and C01 body',
    selected_body_sha256=hashlib.sha256(body.encode()).hexdigest(),
    flags=flags, caller_flags=caller_flags, scoped_redirect='SafeLock.cpp only', rows=rows,
    source_inputs={str(p): sha(p) for p in sorted(dependencies)},
    tools={str(p): sha(p) for p in [ROOT/'build/pass/encbound_pass.so', ROOT/'tools/encbound-cc.sh',
        ROOT/'tools/mark_appdata_sections.sh', ROOT/'config/integration.env', ROOT/'runtime/cxx_services.c']},
    artifacts={str(p.relative_to(OUT)): sha(p) for p in OUT.rglob('*') if p.is_file() and p.name != 'results.json'},
    limits=['Restore completion intentionally terminates; no original restore support or successful completion.',
            'No full private-library object rebuild, final enclave link/audit, or C01 execution.',
            'Native callback tests do not establish SDK SIM/hardware behavior or spatial prevention.',
            'Mutex stubs still require enforced serial/nonreentrant application entry.'])
(OUT/'results.json').write_text(json.dumps(record, indent=2)+'\n')
print('CRUST TERMINAL RESTORE MATRIX PASS', OUT/'results.json', flush=True)
