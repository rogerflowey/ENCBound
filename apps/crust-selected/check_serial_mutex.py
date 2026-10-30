#!/usr/bin/env python3
"""Build/test only the owner-authorized Crust application mutex adaptation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHARED = ROOT/'apps/serial-mutex'
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--checkout', type=Path, default=ROOT/'build/paper-sources/crust-sworker')
parser.add_argument('--out-dir', type=Path, default=ROOT/'build/crust-selected/shared-serial-mutex-v1/all-compat-v1')
args = parser.parse_args()
OUT = args.out_dir.resolve()
OUT.mkdir(parents=True, exist_ok=True)
(OUT/'results.json').unlink(missing_ok=True)
rows = []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(label, command, env=None, expected=0):
    command = list(map(str, command))
    result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=60)
    log = OUT/(label+'.log')
    log.write_text(result.stdout+result.stderr)
    rows.append(dict(label=label, command=command, returncode=result.returncode,
                     expected_returncode=expected, log=str(log), log_sha256=sha(log)))
    if result.returncode != expected:
        raise RuntimeError(f'{label}: {result.returncode}, expected {expected}\n{result.stdout}{result.stderr}')
    print(label, 'PASS', flush=True)
    return result.stdout


pins = json.loads((HERE/'pins.json').read_text())
source = OUT/'source'
source.mkdir(exist_ok=True)
for name, expected in pins['files'].items():
    content = subprocess.check_output(['git', '-C', str(args.checkout), 'show', pins['revision']+':'+name])
    assert hashlib.sha256(content).hexdigest() == expected, name
    (source/Path(name).name).write_bytes(content)
run('pass-build', ['make', '-C', ROOT/'pass'])
flags = ['-std=c++17', '-O2', '-fno-exceptions', '-fno-rtti', '-fno-common', '-fno-builtin',
         '-fvisibility=hidden', '-fpie', '-ffunction-sections', '-fdata-sections',
         '-nostdinc', '-nostdinc++', '-I'+str(SDK/'include/tlibc'), '-I'+str(SDK/'include'),
         '-I'+str(SHARED), '-I'+str(HERE), '-I'+str(source)]
inputs = [SHARED/'serial_mutex.cpp', source/'SafeLock.cpp']


def scoped_flags(unit):
    return ['-include', str(SHARED/'serial_mutex_redirect.h')] if unit.name == 'SafeLock.cpp' else []


definitions = set()
for unit in inputs:
    ir = OUT/(unit.stem+'.frontend.ll')
    run('frontend-'+unit.stem, ['clang++-21', *flags, *scoped_flags(unit), '-S', '-emit-llvm', unit, '-o', ir])
    definitions.update(re.findall(r'^define .*?@([^ (]+)\(', ir.read_text(), re.M))
admitted = OUT/'admitted.txt'
admitted.write_text('\n'.join(sorted(definitions))+'\n')
assert not {'sgx_thread_mutex_lock', 'sgx_thread_mutex_unlock'} & definitions

for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    work = OUT/profile
    work.mkdir(exist_ok=True)
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted),
               ENCBOUND_CXX_EH='0', ENCBOUND_KEEP_GEP_FLAGS='0', ENCBOUND_POST_INSTCOMBINE='0')
    application_objects = []
    for unit in inputs:
        obj = work/(unit.stem+'.o')
        obj.unlink(missing_ok=True)
        run('application-'+profile+'-'+unit.stem,
            [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
             unit, obj, *flags, *scoped_flags(unit)], env)
        settings = json.loads(obj.with_suffix('.integration.json').read_text())['settings']
        assert settings['ENCBOUND_PROFILE'] == profile
        assert settings['ENCBOUND_INTEGRATION_PRESET'] == 'all-compat-v1'
        for feature in ('CALLBACKS', 'AGGREGATE_ABI', 'CXX_ALLOCATIONS', 'ATOMICS', 'VIRTUALS',
                        'VARIADICS', 'PROTECTED_GLOBALS', 'CXX_LIFECYCLE', 'VLA'):
            assert settings['ENCBOUND_'+feature] == '1', (profile, feature)
        symbols = run('symbols-'+profile+'-'+unit.stem, ['llvm-nm-21', obj])
        assert not re.search(r'\bsgx_thread_mutex_(?:lock|unlock)\b', symbols), symbols
        placed = work/(unit.stem+'.placed.o')
        run('placement-'+profile+'-'+unit.stem,
            [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/mark_appdata_sections.sh', obj, placed], env)
        application_objects.append(placed)

    # Native trusted driver, synthetic platform and real checking runtime.
    # The redirect is intentionally absent from ALL trusted compilation commands.
    trusted_flags = ['-O2', '-g', '-I'+str(ROOT/'include'), '-I'+str(ROOT/'runtime'),
                     '-I'+str(ROOT/'sdk'), '-I'+str(ROOT/'tests')]
    if profile != 'BASELINE':
        trusted_flags += ['-DENCBOUND_PROTECTED']
    if profile == 'MAC27':
        trusted_flags += ['-DENCBOUND_MAC27']
    trusted_sources = [ROOT/'sdk/boundary_support.c']
    if profile != 'BASELINE':
        trusted_sources += [ROOT/'tests/fake_platform.c']
        trusted_sources += [ROOT/'runtime'/f'{name}.c' for name in
                            ('siphash', 'runtime', 'capability', 'allocator', 'allocations')]
    trusted_objects = []
    for unit in trusted_sources:
        obj = work/('trusted-'+unit.stem+'.o')
        run('trusted-'+profile+'-'+unit.stem, ['clang-21', *trusted_flags,
            '-MMD', '-MF', obj.with_suffix('.d'), '-c', unit, '-o', obj])
        trusted_objects.append(obj)
    harness = work/'native-driver.o'
    run('native-driver-'+profile, ['clang++-21', '-std=c++17', '-fno-exceptions', '-fno-rtti',
        *trusted_flags, '-I'+str(SHARED), '-I'+str(HERE), '-I'+str(source), '-I'+str(SDK/'include'),
        '-MMD', '-MF', harness.with_suffix('.d'), '-c', HERE/'native.cpp', '-o', harness])
    exe = work/'native'
    run('link-'+profile, ['clang++-21', *application_objects, *trusted_objects, harness, '-o', exe])
    output = run('native-'+profile, [exe])
    assert 'CRUST SERIAL MUTEX NATIVE PASS' in output

    if profile == 'BASELINE':
        # A missing local redirect must be caught by the same runtime oracle.
        raw = work/'SafeLock.raw-control.o'
        run('negative-build-raw-routing', ['clang++-21', *flags, '-c', source/'SafeLock.cpp', '-o', raw])
        negative = work/'native-raw-control'
        run('negative-link-raw-routing', ['clang++-21', application_objects[0], raw,
            *trusted_objects, harness, '-o', negative])
        run('negative-native-raw-routing', [negative], expected=42)

dependencies = {p for directory in (HERE, SHARED) for p in directory.iterdir()
                if p.suffix in ('.cpp', '.h', '.py', '.json')}
for dep in OUT.rglob('*.d'):
    for name in shlex.split(dep.read_text().replace('\\\n', ' ').partition(':')[2]):
        path = Path(name).resolve()
        if path.is_file():
            dependencies.add(path)
artifacts = {str(p.relative_to(OUT)): sha(p) for p in OUT.rglob('*')
             if p.is_file() and p.name != 'results.json'}
result = dict(evidence_class='native mutex adaptation and serial-gate controls; no Crust enclave execution',
    pins=pins, application_flags=flags, component='shared app_serial_mutex_lock/unlock', scoped_redirect='SafeLock.cpp only', rows=rows,
    source_inputs={str(p): sha(p) for p in sorted(dependencies)},
    tools={str(p): sha(p) for p in [ROOT/'build/pass/encbound_pass.so', ROOT/'tools/encbound-cc.sh',
        ROOT/'tools/mark_appdata_sections.sh', ROOT/'config/integration.env', SDK/'include/sgx_thread.h']},
    artifacts=artifacts,
    limits=['Mutex synchronization omitted in all profiles, requires serial nonreentrant admission.',
            'Native SDK symbols are spies; no SDK SIM/hardware mutex or whole-Crust execution.',
            'Restore callback adaptation is checked separately by check_restore_stub.py.'])
(OUT/'results.json').write_text(json.dumps(result, indent=2)+'\n')
print('CRUST SERIAL MUTEX MATRIX PASS', OUT/'results.json')
