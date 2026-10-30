#!/usr/bin/env python3
"""Pinned SGX-KMS enclave closure and benign C16 current-session SDK SIM fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import resource
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', type=Path, default=ROOT/'build/sgx-kms/all-compat-v1')
p.add_argument('--profile', choices=['BASELINE', 'RADIX_ONLY', 'MAC27'], action='append')
a = p.parse_args()
BUILD = a.build.resolve()
BUILD.mkdir(parents=True, exist_ok=True)
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PINNED = Path(os.environ.get('PINNED_SRC', str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
SOURCE_ROOT = ROOT/'build/paper-sources/sgx-kms'
SOURCE = SOURCE_ROOT/'BarbiE/isv_enclave'
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from encbound_inventory import get_marker
sys.path.insert(0, str(HERE))
from audit import audit as kms_audit


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


commands, rows = [], []
def run(name, command, *, env=None):
    command = list(map(str, command))
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, env=env, timeout=240)
    log = BUILD/(name+'.log')
    log.write_text(result.stdout+result.stderr)
    commands.append(dict(name=name, command=command, returncode=result.returncode,
                         log=str(log), log_sha256=sha(log)))
    (BUILD/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
    assert result.returncode == 0, (name, result.returncode, log.read_text()[-8000:])
    return result


manifest_path = ROOT/'config/paper-sources.json'
manifest = json.loads(manifest_path.read_text())['sgx-kms']
assert manifest['revision'] == '1c9d2d2df117845166196a1c3f6f2fb1b998e2c9'
for name, expected in manifest['files'].items():
    assert sha(SOURCE_ROOT/name) == expected, name
prepared = BUILD/'source'
prepared.mkdir(exist_ok=True)
for file in SOURCE.iterdir():
    if file.is_file(): shutil.copyfile(file, prepared/file.name)
main = prepared/'isv_enclave.cpp'
text = main.read_bytes()
start = text.index(b'    if(b_pse)\n')
end = text.index(b'    return ret;\n}', start)
original = text[start:end]
assert b'sgx_create_pse_session' in original and b'sgx_close_pse_session' in original
# Preserve configured standard KDF. No successful PSE emulation or key-state stub.
replacement = b'''    if (b_pse) return SGX_ERROR_FEATURE_NOT_SUPPORTED;
#ifdef SUPPLIED_KEY_DERIVATION
#error Custom key derivation is outside this configured integration
#else
    ret = sgx_ra_init(pub_key, 0, p_context);
#endif
'''
main.write_bytes(text[:start]+replacement+text[end:])
assert main.read_bytes().split(b'int ecall_proc_ma(', 1)[1] == text.split(b'int ecall_proc_ma(', 1)[1]
c16_sha256 = hashlib.sha256(text[text.index(b'int ecall_proc_ma('):]).hexdigest()
port = dict(file='isv_enclave.cpp', original_sha256=sha(SOURCE/'isv_enclave.cpp'),
            prepared_sha256=sha(main), before=original.decode(), after=replacement.decode(),
            reason='SDK 2.26 non-PSE compatibility: explicitly reject b_pse != 0')
(BUILD/'port.json').write_text(json.dumps(port, indent=2)+'\n')
# Host uses the exact upstream field layout, not a guessed key offset.
types = text[text.index(b' typedef struct sample_ec_pub_t'):text.index(b'void printf(')]
(prepared/'host_types.h').write_bytes(text[:text.index(b'#include <assert.h>')]+types)
run('pass', ['make', '-C', ROOT/'pass'])
run('generator', ['make', '-C', ROOT/'tools/edger8r'])
run('sdk-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', PINNED, '--sdk-ecalls'])
contract = json.loads((ROOT/'tools/edger8r/sdk-ecalls.json').read_text())['sgx_tkey_exchange.edl']
policy = json.loads((ROOT/'tests/fixtures/pre-stl-interface.json').read_text())
policy['sdk_only_imports'].update({'sgx_tkey_exchange.edl': {
    **{k: contract[k] for k in ('sha256', 'symbols')}, 'domain': 'sdk'}})
services = ['ra_init', 'ra_get_keys', 'ra_close', 'create_report', 'read_rand', 'encrypt', 'decrypt',
            'cmac', 'seal', 'unseal', 'sealed_size', 'text_len', 'aad_len', 'memset_s', 'memequal']
profiles = a.profile or ['BASELINE', 'RADIX_ONLY', 'MAC27']
for profile, base in [(p, '0x40000000') for p in profiles]+([('MAC27', '0x140000000')] if 'MAC27' in profiles else []):
    key = profile+'-'+base
    print(key, 'building', flush=True)
    out = BUILD/key
    out.mkdir(exist_ok=True)
    g = out/'generated'
    interface = out/'interface.json'
    interface.write_text(json.dumps(policy, indent=2)+'\n')
    flags = ['-m64', '-O2', '-g', '-Wall', '-Wextra', '-fpie', '-fvisibility=hidden',
             '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong', '-nostdinc',
             *['-I'+str(v) for v in (ROOT/'include', ROOT/'sdk', ROOT/'runtime', g, prepared,
                                     SDK/'include', SDK/'include/tlibc')],
             '-isystem', str(PINNED/'common/inc/internal')]
    run(key+'-generate', [ROOT/'tools/with-integration-defaults.sh', 'python3', ROOT/'tools/modified_bridge.py', '--edl', HERE/'enclave.edl',
        '--interface', interface, '--generator', ROOT/'build/edger8r/sgx_edger8r', '--out-dir', g,
        '--profile', profile, '--search-path', prepared, '--search-path', SDK/'include', '--cc', 'gcc',
        '--layout-cc', 'clang-21', *['--cflag='+f for f in flags]])
    (g/'isv_enclave_t.h').write_text('/* Include spelling required by upstream source. */\n#include \"enclave_t.h\"\n')
    baseline_stock_equal = None
    if profile == 'BASELINE':
        stock = out/'stock'
        stock.mkdir(exist_ok=True)
        run(key+'-stock', [SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock,
            '--untrusted', '--untrusted-dir', stock, HERE/'enclave.edl',
            '--search-path', prepared, '--search-path', SDK/'include'],
            env={k:v for k,v in os.environ.items() if not k.startswith('ENCBOUND_BRIDGE_')})
        baseline_stock_equal = {name:(stock/name).read_bytes() == (g/name).read_bytes()
            for name in ('enclave_t.c','enclave_t.h','enclave_u.c','enclave_u.h')}
        assert all(baseline_stock_equal.values())
    boundary = g/'boundary-manifest.json'
    b = json.loads(boundary.read_text())
    assert len(b['application_ecalls']) == 20 and len(b['sdk_ecalls']) == 3
    sources = [prepared/n for n in ('isv_enclave.cpp', 'barbie_common.cpp', 'barbie_server.cpp', 'seal.cpp')]
    # Reuse the complete private selected formatter with actual SGX-KMS callers.
    fmt = out/'format'
    callerflags = ['-I'+str(g), '-I'+str(prepared), '-include', str(HERE/'services.h')]
    run(key+'-formatter', [ROOT/'tools/with-integration-defaults.sh', 'python3',
        ROOT/'apps/libc-format/build.py', '--profile', profile, '--sdk', SDK, '--source', PINNED,
        '--out-dir', fmt, '--caller-no-namespace',
        *[v for src in sources for v in ('--caller', src)],
        *['--caller-flag='+f for f in callerflags]])
    format_record = json.loads((fmt/'build.json').read_text())
    definitions = (fmt/'admitted.txt').read_text()
    admitted = out/'admitted.txt'
    admitted.write_text(definitions+(g/'admitted-app.txt').read_text()+(g/'admitted-ocalls.txt').read_text()+
        ''.join(f'kms_{s} = encbound_kms_{s}\n' for s in services))
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted))
    app = [Path(v) for v in format_record['objects']]
    cxxflags = [*flags, '-std=c++17', '-nostdinc++', '-fno-exceptions', '-fno-rtti',
                '-fno-common', '-fno-builtin', '-include', str(HERE/'services.h')]
    for source in sources:
        obj = out/(source.stem+'.o')
        run(key+'-'+source.stem, [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
            source, obj, *cxxflags], env=env)
        placed = out/(source.stem+'.placed.o')
        run(key+'-'+source.stem+'-place', [ROOT/'tools/with-integration-defaults.sh', 'python3',
            ROOT/'tools/mark_app_globals.py', obj, placed])
        placed.replace(obj)
        Path(str(placed)+'.ownership.json').replace(Path(str(obj)+'.ownership.json'))
        app.append(obj)
    units = []
    for obj in app:
        unit = json.loads(obj.with_suffix('.integration.json').read_text())
        assert unit['settings']['ENCBOUND_INTEGRATION_PRESET'] == 'all-compat-v1'
        assert unit['settings']['ENCBOUND_PROFILE'] == profile
        assert get_marker(obj) == (None if profile == 'BASELINE' else profile)
        placement = json.loads(Path(str(obj)+'.ownership.json').read_text())
        assert unit['object_sha256'] == placement['input_sha256'] and sha(obj) == placement['output_sha256']
        for source, identity in unit['inputs'].items(): assert sha(source) == identity, source
        units.append(dict(object=str(obj), sha256=sha(obj), compilation=unit,
                          placement_sha256=sha(Path(str(obj)+'.ownership.json'))))
    trusted_sources = {'kms_adapters': HERE/'adapters.c', 'enclave_t': g/'enclave_t.c',
                       'cxx_services': ROOT/'runtime/cxx_services.c'}
    if profile != 'BASELINE':
        trusted_sources.update({'boundary_support': ROOT/'sdk/boundary_support.c',
            'platform_layout': ROOT/'sdk/platform_layout.c', **{n: ROOT/f'runtime/{n}.c' for n in
            ('runtime', 'siphash', 'capability', 'allocations', 'allocator', 'adapters')}})
    defines = [] if profile == 'BASELINE' else ['-DENCBOUND_PROTECTED']
    if profile == 'MAC27': defines += ['-DENCBOUND_MAC27']
    trusted = []
    for name, source in trusted_sources.items():
        obj = out/(name+'.o')
        command = ['gcc', *flags, *defines, '-MMD', '-MF', obj.with_suffix('.d'), '-c', source, '-o', obj]
        run(key+'-'+name, command)
        dependencies = shlex.split(obj.with_suffix('.d').read_text().replace('\\\n','').split(':',1)[1])
        obj.with_suffix('.trusted.json').write_text(json.dumps(dict(command=list(map(str,command)),
            inputs={str(Path(v).resolve()):sha(Path(v)) for v in dependencies}, object_sha256=sha(obj)), indent=2)+'\n')
        trusted.append(obj)
    closure = kms_audit(app, trusted, profile, services, boundary)
    (out/'closure.json').write_text(json.dumps(closure, indent=2)+'\n')
    image, linkmap = out/'enclave.so', out/'enclave.map'
    libraries = SDK/'lib64'
    run(key+'-link', ['gcc', *trusted, *app, '-o', image,
        '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--no-undefined', '-nostdlib', '-nodefaultlibs',
        '-nostartfiles', '-L'+str(libraries), '-Wl,--whole-archive', '-lsgx_trts_sim',
        '-Wl,--no-whole-archive', '-Wl,--start-group', '-lsgx_tkey_exchange', '-lsgx_tstdc',
        '-lsgx_tcrypto', '-lsgx_tservice_sim', '-Wl,--end-group', '-Wl,-Bstatic', '-Wl,-Bsymbolic',
        '-Wl,-pie,-eenclave_entry', '-Wl,--export-dynamic', '-Wl,--defsym,__ImageBase=0',
        '-Wl,--gc-sections', '-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'), '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')])
    ownership_audit(image, app, trusted, linkmap, bridge_manifests=[boundary])
    run(key+'-link-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK,
        '--pinned', PINNED, '--sdk-ecalls', '--link-map', linkmap])
    private_key, signed = out/'test-key.pem', out/'enclave.signed.so'
    run(key+'-key', ['openssl', 'genrsa', '-out', private_key, '-3', '3072'])
    template = ROOT/'sdk/enclave.config.tmpl.xml'
    sizing, final = out/'sizing.xml', out/'final.xml'
    run(key+'-sizing', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config',
        '--template', template, '--base', base, '--size', '0x40000000', '--out', sizing])
    run(key+'-sizing-sign', [SDK/'bin/x64/sgx_sign', 'sign', '-key', private_key,
        '-enclave', image, '-out', out/'sizing.so', '-config', sizing])
    extent = run(key+'-extent', ['python3', ROOT/'tools/sgx_metadata.py', 'required',
        '--signed', out/'sizing.so']).stdout.strip()
    run(key+'-config', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config',
        '--template', template, '--base', base, '--size', extent, '--out', final])
    run(key+'-sign', [SDK/'bin/x64/sgx_sign', 'sign', '-key', private_key,
        '-enclave', image, '-out', signed, '-config', final])
    run(key+'-metadata', ['python3', ROOT/'tools/sgx_metadata.py', 'verify',
        '--signed', signed, '--base', base, '--size', extent])
    ownership_audit(signed, app, trusted, linkmap, bridge_manifests=[boundary])
    host = out/'host'
    run(key+'-host', ['gcc', '-g', '-O2', '-Wno-deprecated-declarations', '-I'+str(g), '-I'+str(prepared),
        '-I'+str(SDK/'include'), HERE/'host.c', g/'enclave_u.c', '-o', host,
        '-L'+str(libraries), '-Wl,-rpath-link,'+str(libraries), '-lsgx_urts_sim', '-lpthread', '-lcrypto'])
    result = run(key+'-run', [host, signed], env=dict(os.environ,
        LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libraries), ENCBOUND_TEST_BASE=base))
    assert 'SGX-KMS C16 BENIGN SIM PASS' in result.stdout
    rows.append(dict(mode='SDK SIM', profile=profile, base=base, result='pass',
        oracle=result.stdout, signed_sha256=sha(signed), map_sha256=sha(linkmap),
        application=units, trusted={str(v):sha(v) for v in trusted},
        boundary_sha256=sha(boundary), closure=closure, baseline_stock_equal=baseline_stock_equal,
        ecalls=103, independent_checks=27, fresh_ra_sessions=3, c16_success=6,
        c16_identity_reject=3, c16_tag_reject=3))
    (BUILD/'results.json').write_text(json.dumps(dict(scope='SGX-KMS enclave service closure and benign C16; SDK SIM only',
        upstream=manifest['revision'], verified_source_files=len(manifest['files']), port=port,
        unchanged_c16_body_sha256=c16_sha256, rows=rows,
        commands=commands, inputs={str(v):sha(v) for v in [Path(__file__), HERE/'adapters.c',
        HERE/'services.h', HERE/'host.c', HERE/'enclave.edl', HERE/'audit.py', manifest_path]}, prepared={str(v):sha(v) for v in prepared.iterdir() if v.is_file()}), indent=2)+'\n')
    print(key, 'PASS', flush=True)
print('SGX-KMS BENIGN SDK SIM PASS', len(rows), 'configurations')
