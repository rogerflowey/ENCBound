#!/usr/bin/env python3
"""Build/audit/run the adapted Crust incomplete-transfer enclave in SDK SIM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk'))).resolve()
PINNED = Path(os.environ.get('PINNED_SRC', str(ROOT/'deps/intel-sgx'))).resolve()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out-dir', type=Path, default=ROOT/'build/crust-selected/enclave-v1/all-compat-v1')
parser.add_argument('--checkout', type=Path, default=ROOT/'build/paper-sources/crust-sworker')
parser.add_argument('--profile', choices=('BASELINE', 'RADIX_ONLY', 'MAC27'), action='append')
args = parser.parse_args()
OUT = args.out_dir.resolve()
OUT.mkdir(parents=True, exist_ok=True)
(OUT/'results.json').unlink(missing_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from check_early_bootstrap import audit as bootstrap_audit
sys.path.insert(0, str(HERE))
from audit import audit as closure_audit

commands, rows = [], []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(name, command, env=None, expected=0):
    command = list(map(str, command))
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=600)
    log = OUT/(name+'.log')
    log.write_text(result.stdout+result.stderr)
    commands.append(dict(name=name, command=command, returncode=result.returncode,
        expected_returncode=expected, log=str(log), log_sha256=sha(log)))
    (OUT/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
    if result.returncode != expected:
        raise RuntimeError(f'{name}: {result.returncode}, expected {expected}\n{log.read_text()[-8000:]}')
    print(name, 'PASS', flush=True)
    return result.stdout+result.stderr


# Freeze workload-local tooling/headers so another integration's builds cannot
# silently change this matrix's compiler or prepared-library inputs.
env = dict(os.environ, SGX_SDK=str(SDK), PINNED_SRC=str(PINNED),
    ENCBOUND_PLUGIN=str(OUT/'toolchain/pass/encbound_pass.so'),
    ENCBOUND_LIBCXX_PREPARED=str(OUT/'libcxx-prepared'), ENCBOUND_CXX_EH='0',
    ENCBOUND_KEEP_GEP_FLAGS='0', ENCBOUND_POST_INSTCOMBINE='0')
run('pass', ['make', '-C', ROOT/'pass', 'BUILD='+str(OUT/'toolchain/pass')], env)
run('generator', ['make', '-C', ROOT/'tools/edger8r', 'BUILD='+str(OUT/'toolchain/edger8r')], env)
run('sdk-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', PINNED], env)
run('libcxx-prepare', ['python3', ROOT/'apps/libcxx/prepare.py'], env)

pins = json.loads((HERE/'pins.json').read_text())
source = OUT/'source'
source.mkdir(exist_ok=True)
for name, expected in pins['files'].items():
    content = subprocess.check_output(['git', '-C', str(args.checkout), 'show', pins['revision']+':'+name])
    assert hashlib.sha256(content).hexdigest() == expected, name
    (source/Path(name).name).write_bytes(content)
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
(source/'SafeLock_selected.cpp').write_text('#include "serial_mutex_redirect.h"\n#include "SafeLock.cpp"\n')
enum_decl = re.search(r'typedef enum _ecall_store_type_t \{.*?\} ecall_store_type_t;',
                      (source/'Parameter.h').read_text(), re.S).group(0)
# Parameter.h also defines unrelated C-linkage constants. Use only the exact
# transport enum in generated C; application C++ still consumes the full header.
(source/'selected-types.h').write_text('#ifndef CRUST_SELECTED_TYPES_H\n#define CRUST_SELECTED_TYPES_H\n'
    '#include <stdint.h>\n#include <stddef.h>\n#include "CrustStatus.h"\n'+enum_decl+'\n#endif\n')
declaration = next(line.strip() for line in (source/'Enclave.edl').read_text().splitlines()
                   if 'public crust_status_t ecall_safe_store2(' in line)
# Original selected ECALL plus finite application/trusted observation endpoints.
# SDK imports supply stock SDK-only event/CPUID services, not app admissions.
(source/'enclave.edl').write_text('enclave { include "selected-types.h"\n'
    'from "sgx_tstdc.edl" import *;\ntrusted {\n'+declaration+'\n'
    'public int crust_selected_snapshot(uint32_t key, [out, size=bytes] uint8_t *output, size_t bytes);\n'
    'public int layout_checks();\npublic int crust_selected_serial_check();\n};\n};\n')
application_sources = [source/'selected.cpp', source/'dispatch.cpp', source/'SafeLock_selected.cpp',
    ROOT/'apps/serial-mutex/serial_mutex.cpp', HERE/'restore_stub.cpp', HERE/'snapshot.cpp']
wrap = [ROOT/'tools/with-integration-defaults.sh']
profiles = args.profile or ['BASELINE', 'RADIX_ONLY', 'MAC27']
for profile in profiles:
    # One fresh library build per profile; high-base MAC27 reuses exactly these
    # placed library bytes and gets its own application/trusted/image builds.
    lib = OUT/('libcxx-'+profile)
    caller_flags = ['-I'+str(source), '-I'+str(HERE), '-I'+str(ROOT/'apps/serial-mutex')]
    run(profile+'-libcxx', [*wrap, 'python3', ROOT/'apps/libcxx/build.py', '--profile', profile,
        '--out-dir', lib, *[v for unit in application_sources for v in ('--caller', unit)],
        *['--caller-flag='+flag for flag in caller_flags]], env)
    library = json.loads((lib/'build.json').read_text())
    for base in (['0x40000000', '0x140000000'] if profile == 'MAC27' else ['0x40000000']):
        label = profile+'-'+base
        out = OUT/label
        out.mkdir(exist_ok=True)
        g = out/'generated'
        includes = ['-I'+str(p) for p in (source, HERE, g, ROOT/'include', ROOT/'sdk', ROOT/'runtime',
            ROOT/'apps/serial-mutex', SDK/'include', SDK/'include/tlibc')]
        common = ['-m64', '-O2', '-g', '-nostdinc', '-fvisibility=hidden', '-fpie',
            '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong', *includes,
            '-isystem', str(PINNED/'common/inc/internal')]
        run(label+'-bridge', ['python3', ROOT/'tools/modified_bridge.py', '--edl', source/'enclave.edl',
            '--interface', ROOT/'tests/fixtures/crust/boundary-interface.json',
            '--generator', OUT/'toolchain/edger8r/sgx_edger8r', '--profile', profile, '--out-dir', g,
            '--search-path', source, '--search-path', SDK/'include', '--layout-cc', 'clang-21',
            *['--cflag='+flag for flag in common]], env)
        baseline_stock_equal = None
        if profile == 'BASELINE':
            stock = out/'stock'
            stock.mkdir(exist_ok=True)
            run(label+'-stock', [SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock,
                '--untrusted', '--untrusted-dir', stock, source/'enclave.edl',
                '--search-path', source, '--search-path', SDK/'include'],
                {k:v for k,v in env.items() if not k.startswith('ENCBOUND_BRIDGE_')})
            baseline_stock_equal = {name:(g/name).read_bytes() == (stock/name).read_bytes()
                for name in ('enclave_t.c', 'enclave_t.h', 'enclave_u.c', 'enclave_u.h')}
            assert all(baseline_stock_equal.values())
        admitted = out/'admitted.txt'
        admitted.write_text((lib/'admitted.txt').read_text()+(g/'admitted-app.txt').read_text()+
                            (g/'admitted-ocalls.txt').read_text())
        row_env = dict(env, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted))
        app = [Path(obj) for obj in library['objects']]
        for unit in application_sources+[ROOT/'libc/errno.c']:
            obj = out/(unit.stem+'.o')
            obj.unlink(missing_ok=True)
            flags = [*library['flags'], *includes] if unit.suffix == '.cpp' else [*common, '-fno-common', '-fno-builtin']
            run(label+'-app-'+unit.stem, [*wrap, ROOT/'tools/encbound-cc.sh', unit, obj, *flags], row_env)
            placed = out/(unit.stem+'.placed.o')
            run(label+'-place-'+unit.stem, [*wrap, ROOT/'tools/mark_appdata_sections.sh', obj, placed], row_env)
            placed.replace(obj)
            Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
            app.append(obj)

        trusted_sources = {'boundary_support': ROOT/'sdk/boundary_support.c',
            'enclave_t': g/'enclave_t.c', 'cxx_allocations': ROOT/'runtime/cxx_allocations.c',
            'cxx_services': ROOT/'runtime/cxx_services.c', 'layout_checks': ROOT/'tests/fixtures/crust/layout_checks.c',
            'serial_check': HERE/'serial_check.c'}
        defines = ['-DENCBOUND_CXX_BASELINE'] if profile == 'BASELINE' else ['-DENCBOUND_PROTECTED']
        if profile != 'BASELINE':
            trusted_sources = {'early_bootstrap': ROOT/'sdk/early_bootstrap.c', **trusted_sources,
                'platform_layout': ROOT/'sdk/platform_layout.c', **{name:ROOT/f'runtime/{name}.c' for name in
                ('cxx_lifecycle', 'runtime', 'capability', 'siphash', 'allocations', 'allocator', 'adapters')}}
        if profile == 'MAC27': defines += ['-DENCBOUND_MAC27']
        trusted = []
        for name, unit in trusted_sources.items():
            obj = out/(name+'.o')
            command = ['gcc', *common, *defines, '-MMD', '-MF', obj.with_suffix('.d'), '-c', unit, '-o', obj]
            run(label+'-trusted-'+name, command, env)
            dependencies = shlex.split(obj.with_suffix('.d').read_text().replace('\\\n', ' ').partition(':')[2])
            obj.with_suffix('.trusted.json').write_text(json.dumps(dict(command=list(map(str, command)),
                inputs={str(Path(name).resolve()):sha(name) for name in dependencies}, object_sha256=sha(obj)), indent=2)+'\n')
            trusted.append(obj)
        image, linkmap = out/'enclave.so', out/'enclave.map'
        run(label+'-link', ['gcc', *trusted, *app, '-o', image,
            '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--no-undefined', '-nostdlib', '-nodefaultlibs',
            '-nostartfiles', '-L'+str(SDK/'lib64'), '-Wl,--whole-archive', '-lsgx_trts_sim',
            '-Wl,--no-whole-archive', '-Wl,--start-group', '-lsgx_tcxx', '-lsgx_tstdc', '-lsgx_tcrypto',
            '-lsgx_tservice_sim', '-Wl,--end-group', '-Wl,-Bstatic', '-Wl,-Bsymbolic',
            '-Wl,-pie,-eenclave_entry', '-Wl,--export-dynamic', '-Wl,--defsym,__ImageBase=0',
            '-Wl,--gc-sections', '-Wl,-Map,'+str(linkmap),
            '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'), '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')], env)
        ownership_audit(image, app, trusted, linkmap, bridge_manifests=[g/'boundary-manifest.json'])

        key, signed = out/'test-key.pem', out/'enclave.signed.so'
        run(label+'-key', ['openssl', 'genrsa', '-out', key, '-3', '3072'], env)
        template = ROOT/'sdk/enclave.config.tmpl.xml'
        run(label+'-sizing', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config',
            '--template', template, '--base', base, '--size', '0x40000000', '--out', out/'sizing.xml'], env)
        run(label+'-sizing-sign', [SDK/'bin/x64/sgx_sign', 'sign', '-key', key, '-enclave', image,
            '-out', out/'sizing.so', '-config', out/'sizing.xml'], env)
        extent = run(label+'-extent', ['python3', ROOT/'tools/sgx_metadata.py', 'required', '--signed', out/'sizing.so'], env).strip()
        run(label+'-config', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config',
            '--template', template, '--base', base, '--size', extent, '--out', out/'final.xml'], env)
        run(label+'-sign', [SDK/'bin/x64/sgx_sign', 'sign', '-key', key, '-enclave', image,
            '-out', signed, '-config', out/'final.xml'], env)
        run(label+'-metadata', ['python3', ROOT/'tools/sgx_metadata.py', 'verify',
            '--signed', signed, '--base', base, '--size', extent], env)
        build = dict(profile=profile, base=base, mode='SDK SIM', pins=pins,
            selected_body_sha256=pins['selected_body_sha256'], library=str(lib),
            library_manifest_sha256=sha(lib/'build.json'),
            app=list(map(str, app)), trusted=list(map(str, trusted)),
            source=str(source), baseline_stock_equal=baseline_stock_equal,
            prepared_manifest=str(OUT/'libcxx-prepared/sources.json'),
            prepared_manifest_sha256=sha(OUT/'libcxx-prepared/sources.json'),
            input_hashes={str(p):sha(p) for p in HERE.iterdir() if p.is_file() and p.suffix in ('.c', '.cpp', '.h', '.py', '.json')},
            tool_hashes={str(p):sha(p) for p in [OUT/'toolchain/pass/encbound_pass.so',
                OUT/'toolchain/edger8r/sgx_edger8r', ROOT/'tools/encbound-cc.sh', ROOT/'config/integration.env']})
        (out/'build.json').write_text(json.dumps(build, indent=2)+'\n')
        closure_audit(out)
        run(label+'-host', ['gcc', '-O2', '-g', '-I'+str(g), '-I'+str(source), '-I'+str(SDK/'include'),
            HERE/'host.c', g/'enclave_u.c', '-o', out/'host', '-L'+str(SDK/'lib64'),
            '-Wl,-rpath-link,'+str(SDK/'lib64'), '-lsgx_urts_sim', '-lpthread'], env)
        runtime_env = dict(env, LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'), ENCBOUND_TEST_BASE=base)
        functional = run(label+'-functional', [out/'host', signed], runtime_env)
        response = json.loads(next(line for line in functional.splitlines() if line.startswith('{')))
        assert response == dict(result='PASS', calls=90, snapshots=44, compared_bytes=22016, retained_buffers=3), response
        assert 'loaded app page permissions: PASS' in functional
        assert 'runtime region isolation and serial gate: PASS' in functional
        run(label+'-completion', [out/'host', signed, 'completion'], runtime_env, expected=-signal.SIGILL)
        script = out/'completion.gdb'
        script.write_text('set pagination off\nset confirm off\nhandle SIGILL stop print\n'
            'break transfer\nrun\nadd-symbol-file '+str(image)+' -o '+base+'\n'
            'break ecall_restore_from_upgrade\ncontinue\nbt 8\ncontinue\nbt 8\n')
        trace = run(label+'-completion-trace', ['gdb', '-q', '-batch', '-x', script,
            '--args', out/'host', signed, 'completion'], runtime_env)
        for expected in ('ecall_restore_from_upgrade', 'ecall_safe_store2', 'SIGILL', 'abort'):
            assert expected in trace, (expected, trace)
        rows.append(dict(profile=profile, base=base, mode='SDK SIM', functional=response,
            signed_sha256=sha(signed), build=str(out), inventory_sha256=sha(out/'inventory.json'),
            terminal_completion_exit=-signal.SIGILL, completion_trace_sha256=sha(OUT/(label+'-completion-trace.log')),
            baseline_stock_equal=baseline_stock_equal))
        (OUT/'results.json').write_text(json.dumps(dict(scope='adapted Crust C01 incomplete-transfer integration; SDK SIM',
            pins=pins, rows=rows, commands=commands, protection=False, hardware=False,
            performance=False, real_restore=False), indent=2)+'\n')
        print(label, 'SDK SIM PASS', response, flush=True)
print('CRUST SELECTED SDK SIM PASS', len(rows), 'configurations', flush=True)
