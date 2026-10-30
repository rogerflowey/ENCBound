#!/usr/bin/env python3
"""Real pinned SDK RA entry implementation, independent peer, SDK SIM only."""
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = ROOT/'build/integration/sdk-ecalls-sim'
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PINNED = Path(os.environ.get('PINNED_SRC', str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
BUILD.mkdir(parents=True, exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from audit_sdk_ecalls import audit as entry_audit
from encbound_inventory import get_marker
from mark_app_globals import sections

rows, commands, trusted_inputs = [], [], {}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(name, command, *, env=None):
    command = list(map(str, command))
    p = subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)
    log = BUILD/(name+'.log')
    log.write_text(p.stdout+p.stderr)
    commands.append(dict(command=command, log=str(log), log_sha256=sha(log), returncode=p.returncode))
    assert p.returncode == 0, (name, p.returncode, log.read_text())
    return p


def denied(case, reason, image, app, trusted, linkmap, manifests):
    try:
        entry_audit(image, app, trusted, linkmap, manifests=manifests)
    except ValueError as e:
        assert reason in str(e), (case, str(e), reason)
        rows.append(dict(mode='final-link audit negative', case=case, result=str(e)))
    else:
        raise AssertionError('invalid SDK entry ownership admitted: '+case)


def move_symbol(source, destination, symbol, address):
    """Mutation control: edit only an ELF symbol value, without executing it."""
    data = bytearray(source.read_bytes())
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shsize, count = struct.unpack_from('<HH', data, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(count)]
    changed = 0
    for header in headers:
        if header[1] != 2:  # SHT_SYMTAB
            continue
        strings = headers[header[6]]
        names = data[strings[4]:strings[4]+strings[5]]
        for offset in range(header[4], header[4]+header[5], header[9]):
            name_offset = struct.unpack_from('<I', data, offset)[0]
            name = names[name_offset:names.index(0, name_offset)].decode()
            if name == symbol:
                struct.pack_into('<Q', data, offset+8, address)
                changed += 1
    assert changed == 1, (symbol, changed)
    destination.write_bytes(data)


run('pass', ['make', '-C', ROOT/'pass'])
run('generator', ['make', '-C', ROOT/'tools/edger8r'])
run('pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', PINNED])
contract = json.loads((ROOT/'tools/edger8r/sdk-ecalls.json').read_text())['sgx_tkey_exchange.edl']
policy = json.loads((ROOT/'tests/fixtures/pre-stl-interface.json').read_text())
policy['sdk_only_imports']['sgx_tkey_exchange.edl'] = {
    k: contract[k] for k in ('sha256', 'symbols')}
policy['sdk_only_imports']['sgx_tkey_exchange.edl']['domain'] = 'sdk'
libraries = SDK/'lib64'
for profile, base in [('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
                      ('MAC27', '0x40000000'), ('MAC27', '0x140000000')]:
    key = profile+'-'+base
    out = BUILD/key
    out.mkdir(exist_ok=True)
    g = out/'generated'
    interface = out/'interface.json'
    interface.write_text(json.dumps(policy, indent=2)+'\n')
    flags = ['-m64', '-O2', '-g', '-Wall', '-Wextra', '-fpie', '-fvisibility=hidden',
             '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong', '-nostdinc',
             *['-I'+str(p) for p in (ROOT/'include', ROOT/'sdk', ROOT/'runtime', g,
                                      SDK/'include', SDK/'include/tlibc')],
             '-isystem', str(PINNED/'common/inc/internal')]
    run(key+'-generate', ['python3', ROOT/'tools/modified_bridge.py', '--edl', HERE/'probe.edl',
        '--interface', interface, '--generator', ROOT/'build/edger8r/sgx_edger8r', '--out-dir', g,
        '--profile', profile, '--search-path', SDK/'include', '--cc', 'gcc',
        '--layout-cc', 'clang-21', *['--cflag='+f for f in flags]])
    manifest = g/'boundary-manifest.json'
    admitted = out/'admitted.txt'
    admitted.write_text((g/'admitted-app.txt').read_text()+''.join(
        f'fixture_ra_{name} = encbound_fixture_ra_{name}\n' for name in ('init', 'keys', 'close')))
    app = out/'application.o'
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted))
    run(key+'-application', [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
        HERE/'application.c', app, *flags, '-fno-common', '-fno-builtin'], env=env)
    placed = out/'placed.o'
    run(key+'-placement', [ROOT/'tools/with-integration-defaults.sh', 'python3',
        ROOT/'tools/mark_app_globals.py', app, placed])
    placed.replace(app)
    Path(str(placed)+'.ownership.json').replace(Path(str(app)+'.ownership.json'))
    unit = json.loads(app.with_suffix('.integration.json').read_text())
    assert unit['settings']['ENCBOUND_INTEGRATION_PRESET'] == 'all-compat-v1'
    assert get_marker(app) == (None if profile == 'BASELINE' else profile)
    placement = json.loads(Path(str(app)+'.ownership.json').read_text())
    assert unit['object_sha256'] == placement['input_sha256'] and sha(app) == placement['output_sha256']
    for source, identity in unit['inputs'].items():
        assert sha(source) == identity
    sources = {'fixture': HERE/'trusted.c', 'probe_t': g/'probe_t.c'}
    if profile != 'BASELINE':
        sources.update({'boundary_support': ROOT/'sdk/boundary_support.c',
            'platform_layout': ROOT/'sdk/platform_layout.c', **{n: ROOT/f'runtime/{n}.c' for n in
            ('runtime', 'siphash', 'capability', 'allocations', 'allocator', 'adapters')}})
    defines = [] if profile == 'BASELINE' else ['-DENCBOUND_PROTECTED']
    if profile == 'MAC27':
        defines += ['-DENCBOUND_MAC27']
    trusted = []
    for name, source in sources.items():
        obj = out/(name+'.o')
        run(key+'-'+name, ['gcc', *flags, *defines, '-c', source, '-o', obj])
        trusted_inputs[str(source)] = sha(source)
        trusted.append(obj)
    image, linkmap = out/'enclave.so', out/'enclave.map'
    run(key+'-link', ['gcc', *trusted, app, '-o', image,
        '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--no-undefined', '-nostdlib', '-nodefaultlibs',
        '-nostartfiles', '-L'+str(libraries), '-Wl,--whole-archive', '-lsgx_trts_sim',
        '-Wl,--no-whole-archive', '-Wl,--start-group', '-lsgx_tkey_exchange', '-lsgx_tstdc',
        '-lsgx_tcrypto', '-lsgx_tservice_sim', '-Wl,--end-group', '-Wl,-Bstatic', '-Wl,-Bsymbolic',
        '-Wl,-pie,-eenclave_entry', '-Wl,--export-dynamic', '-Wl,--defsym,__ImageBase=0',
        '-Wl,--gc-sections', '-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'), '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')])
    ownership_audit(image, [app], trusted, linkmap, bridge_manifests=[manifest])
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
    ownership_audit(signed, [app], trusted, linkmap, bridge_manifests=[manifest])
    host = out/'host'
    run(key+'-host', ['gcc', '-g', '-O2', '-Wno-deprecated-declarations', '-I'+str(g),
        '-I'+str(SDK/'include'), HERE/'host.c', g/'probe_u.c', '-o', host,
        '-L'+str(libraries), '-Wl,-rpath-link,'+str(libraries), '-lsgx_urts_sim', '-lpthread', '-lcrypto'])
    p = run(key+'-run', [host, signed], env=dict(os.environ,
        LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libraries), ENCBOUND_TEST_BASE=base))
    assert 'SDK RA SIM PASS calls=46 verified_session_keys=6 valid_msg2=3' in p.stdout
    rows.append(dict(mode='SDK SIM', profile=profile, base=base, result='pass', ecalls=46,
        valid_msg2=3, independently_verified_session_keys=6, image_sha256=sha(signed),
        linkmap_sha256=sha(linkmap), application_unit=unit,
        trusted_objects={str(p): sha(p) for p in trusted}, boundary_manifest_sha256=sha(manifest),
        application_object_sha256=sha(app), ownership_manifest_sha256=sha(Path(str(app)+'.ownership.json'))))
    print(key, 'PASS', flush=True)
    if profile == 'MAC27' and base == '0x40000000':
        denied('missing-manifest', 'boundary manifest', image, [app], trusted, linkmap, [])
        wrong = out/'wrong-manifest.json'
        record = json.loads(manifest.read_text())
        record['application_ecalls'].append(record['sdk_ecalls'][0])
        wrong.write_text(json.dumps(record))
        denied('domain-overlap', 'partition', image, [app], trusted, linkmap, [wrong])
        record = json.loads(manifest.read_text())
        record['inputs'][str(HERE/'probe.edl')] = '0'*64
        # Keep colocated inventories/outputs available so this reaches identity validation.
        wrong = g/'wrong-manifest.json'
        wrong.write_text(json.dumps(record))
        denied('stale-bridge-input', 'stale bridge input', image, [app], trusted, linkmap, [wrong])
        raw = out/'raw.c'
        raw.write_text('extern int sgx_ra_get_ga(int,void*); int leak(void*p){return sgx_ra_get_ga(0,p);}\n')
        rawobj = out/'raw.o'
        run(key+'-raw-object', ['gcc', '-c', raw, '-o', rawobj])
        denied('raw-application-sdk-entry', 'raw SDK entry', image, [app, rawobj], trusted, linkmap, [manifest])
        raw.write_text('int sgx_ra_get_ga(int c,void*p){return c;}\n')
        run(key+'-imposter', ['gcc', '-c', raw, '-o', rawobj])
        denied('trusted-imposter-entry', 'entry defined', image, [app], trusted+[rawobj], linkmap, [manifest])
        badmap = out/'wrong-provider.map'
        badmap.write_text(linkmap.read_text().replace('libsgx_tkey_exchange.a(tkey_exchange.o)',
                                                     'libsgx_tkey_exchange.a(wrong.o)'))
        denied('wrong-sdk-member', 'member not selected', image, [app], trusted, badmap, [manifest])
        altered = out/contract['archive']
        altered.write_bytes((libraries/contract['archive']).read_bytes()+b'changed')
        badmap.write_text(linkmap.read_text().replace(str(libraries/contract['archive']), str(altered)))
        denied('changed-sdk-archive', 'archive identity changed', image, [app], trusted, badmap, [manifest])
        mutated = out/'wrong-address.so'
        address = next(s['address'] for s in sections(image) if s['name'] == '.encbound.globalbss')
        move_symbol(image, mutated, 'sgx_ra_get_ga', address)
        denied('sdk-function-outside-member', 'function resolved outside', mutated, [app], trusted, linkmap, [manifest])
        move_symbol(image, mutated, '_ZL7g_ra_db', address)
        denied('sdk-state-in-application-memory', 'SDK state placed', mutated, [app], trusted, linkmap, [manifest])

(BUILD/'results.json').write_text(json.dumps(dict(scope='SDK SIM fixture; no SGX hardware/full SGX-KMS/quote/IAS result',
    rows=rows, commands=commands, inputs={**trusted_inputs, **{str(p): sha(p) for p in [Path(__file__), HERE/'probe.edl',
    HERE/'application.c', HERE/'trusted.c', HERE/'host.c', ROOT/'tools/audit_sdk_ecalls.py',
    ROOT/'tools/audit_app_globals.py', ROOT/'tools/check_sdk_pins.py']}}), indent=2)+'\n')
print('PINNED SDK RA ECALL SIM PASS:', len(rows), 'functional/audit rows')
