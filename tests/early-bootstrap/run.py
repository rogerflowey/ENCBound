#!/usr/bin/env python3
"""Isolated native controls and real Intel SDK SIM early-startup integration.

Build/link/sign flags are reduced from apps/pre-stl/Makefile (this repository).
No application recipe or compiler lifecycle admission is changed by this probe.
"""
import hashlib
import json
import os
import resource
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = ROOT/'build/integration/early-bootstrap'
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
PINNED = Path(os.environ.get('PINNED_SRC', str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx')))))
BUILD.mkdir(parents=True, exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from check_early_bootstrap import audit, initializers
from encbound_inventory import get_marker

rows = []


def run(name, command, *, env=None, expected=0):
    p = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                       env=env, timeout=120)
    (BUILD/(name+'.log')).write_text(p.stdout+p.stderr)
    if expected is not None:
        assert p.returncode == expected, (name, p.returncode, p.stdout, p.stderr)
    return p


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def denied(image, reason):
    try:
        audit(image)
    except ValueError as e:
        assert reason in str(e), (image, str(e), reason)
    else:
        raise AssertionError('invalid initializer ordering admitted')


inc = ['-I'+str(ROOT/'include'), '-I'+str(ROOT/'sdk')]
bootstrap = BUILD/'bootstrap.o'
run('native-bootstrap', ['clang-21', '-g', '-O2', '-fpie', *inc, '-c',
                         ROOT/'sdk/early_bootstrap.c', '-o', bootstrap])
for fail in (False, True):
    observer = BUILD/('native-fail.o' if fail else 'native.o')
    run('native-compile-'+str(fail), ['clang-21', '-g', '-O2', *inc,
        *(['-DFAIL_INIT'] if fail else []), '-c', HERE/'native.c', '-o', observer])
    exe = BUILD/('native-fail' if fail else 'native')
    run('native-link-'+str(fail), ['clang-21', bootstrap, observer, '-o', exe])
    audit(exe)
    run('native-run-'+str(fail), [exe], expected=71 if fail else 0)
    rows.append(dict(mode='native unit', case='terminal-init-failure' if fail else 'equal-priority-order', result='pass'))
bad = BUILD/'native-bad-order'
run('native-bad-link', ['clang-21', BUILD/'native.o', bootstrap, '-o', bad])
denied(bad, 'not the first')
rows.append(dict(mode='native audit', case='wrong-equal-priority-link-order', result='pass'))
native = BUILD/'native'
raw = bytearray(native.read_bytes())
phoff = struct.unpack_from('<Q',raw,32)[0]
phsize, phcount = struct.unpack_from('<HH',raw,54)
for i in range(phcount):
    ph = struct.unpack_from('<IIQQQQQQ',raw,phoff+i*phsize)
    if ph[0] != 2: continue
    for pos in range(ph[2],ph[2]+ph[5],16):
        if struct.unpack_from('<Q',raw,pos)[0] == 27:
            struct.pack_into('<Q',raw,pos+8,3)
bad = BUILD/'native-bad-dynamic-size'
bad.write_bytes(raw)
denied(bad,'malformed DT_INIT_ARRAY')
rows.append(dict(mode='native audit',case='malformed-dynamic-array-size',result='pass'))
raw = bytearray(native.read_bytes())
init = initializers(native)
shoff = struct.unpack_from('<Q',raw,40)[0]
shsize, shcount = struct.unpack_from('<HH',raw,58)
changed = False
for i in range(shcount):
    sh = struct.unpack_from('<IIQQQQIIQQ',raw,shoff+i*shsize)
    if sh[1] != 4: continue
    for pos in range(sh[4],sh[4]+sh[5],24):
        if struct.unpack_from('<Q',raw,pos)[0] == init['address']+8:
            struct.pack_into('<q',raw,pos+16,init['targets'][0])
            changed = True
assert changed
bad = BUILD/'native-duplicate-bootstrap'
bad.write_bytes(raw)
denied(bad,'more than once')
rows.append(dict(mode='native audit',case='duplicate-bootstrap-target',result='pass'))

run('pass', ['make', '-C', ROOT/'pass'])
run('generator', ['make', '-C', ROOT/'tools/edger8r'])
run('pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', PINNED])
interface = BUILD/'interface.json'
interface.write_text(json.dumps(json.loads((ROOT/'tests/fixtures/pre-stl-interface.json').read_text()), indent=2)+'\n')
libraries = SDK/'lib64'
tail_names = None
for profile, base in [('BASELINE','0x40000000'), ('RADIX_ONLY','0x40000000'),
                      ('MAC27','0x40000000'), ('MAC27','0x140000000')]:
    key = profile+'-'+base
    out = BUILD/key
    out.mkdir(exist_ok=True)
    g = out/'generated'
    flags = ['-m64', '-O2', '-g', '-Wall', '-Wextra', '-fpie', '-fvisibility=hidden',
             '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong',
             '-nostdinc', *inc, '-I'+str(ROOT/'runtime'), '-I'+str(g),
             '-I'+str(SDK/'include'), '-I'+str(SDK/'include/tlibc'),
             '-isystem', str(PINNED/'common/inc/internal')]
    defines = ([] if profile == 'BASELINE' else ['-DENCBOUND_PROTECTED'])
    if profile == 'MAC27':
        defines += ['-DENCBOUND_MAC27']
    run(key+'-generate', ['python3', ROOT/'tools/modified_bridge.py', '--edl', HERE/'probe.edl',
        '--interface', interface, '--generator', ROOT/'build/edger8r/sgx_edger8r',
        '--out-dir', g, '--profile', profile, '--search-path', SDK/'include',
        '--cc', 'gcc', '--layout-cc', 'clang-21', *['--cflag='+f for f in flags]])
    app = out/'app.o'
    appenv = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(HERE/'admitted.txt'))
    run(key+'-app', [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
        HERE/'app.c', app, *flags, '-fno-common', '-fno-builtin'], env=appenv)
    placed = out/'placed.o'
    run(key+'-place', [ROOT/'tools/with-integration-defaults.sh', 'python3',
                      ROOT/'tools/mark_app_globals.py', app, placed])
    placed.replace(app)
    Path(str(placed)+'.ownership.json').replace(Path(str(app)+'.ownership.json'))
    unit = json.loads(app.with_suffix('.integration.json').read_text())
    assert unit['settings']['ENCBOUND_PROFILE'] == profile
    for feature in ('CALLBACKS', 'AGGREGATE_ABI', 'CXX_ALLOCATIONS', 'ATOMICS',
                    'VIRTUALS', 'VARIADICS', 'PROTECTED_GLOBALS'):
        assert unit['settings']['ENCBOUND_'+feature] == '1', feature
    assert unit['settings']['ENCBOUND_INTEGRATION_PRESET'] == 'all-compat-v1'
    for source, value in unit['inputs'].items():
        assert digest(Path(source)) == value
    assert get_marker(app) == (None if profile == 'BASELINE' else profile)
    app_ir = app.with_suffix('.checked.ll').read_text()
    if profile != 'BASELINE':
        for required in ('@encbound_global_cap', '@encbound_stack_mint', '@encbound_require', '@encbound_malloc'):
            assert required in app_ir, required
    undefined = {line.split()[-1] for line in subprocess.check_output(
        ['nm', '--undefined-only', str(app)], text=True).splitlines() if line.strip()}
    allowed = {'malloc', 'free', '__stack_chk_fail'} if profile == 'BASELINE' else {
        'encbound_malloc', 'encbound_free', 'encbound_global_cap', 'encbound_stack_mint',
        'encbound_require', '__stack_chk_fail'}
    assert undefined <= allowed, undefined-allowed
    sources = {'observer': HERE/'observer.c', 'probe_t': g/'probe_t.c'}
    if profile != 'BASELINE':
        sources = {'early_bootstrap': ROOT/'sdk/early_bootstrap.c', **sources,
                   'boundary_support': ROOT/'sdk/boundary_support.c',
                   'platform_layout': ROOT/'sdk/platform_layout.c',
                   **{n: ROOT/f'runtime/{n}.c' for n in
                      ('runtime','siphash','capability','allocations','allocator','adapters')}}
    trusted = []
    for name, source in sources.items():
        obj = out/(name+'.o')
        run(key+'-'+name, ['gcc', *flags, *defines, '-c', source, '-o', obj])
        trusted.append(obj)
    image = out/'enclave.so'
    linkmap = out/'enclave.map'
    link_command = ['gcc', *trusted, app, '-o', image, '-Wl,-z,relro,-z,now,-z,noexecstack',
        '-Wl,--no-undefined', '-nostdlib', '-nodefaultlibs', '-nostartfiles', '-L'+str(libraries),
        '-Wl,--whole-archive', '-lsgx_trts_sim', '-Wl,--no-whole-archive',
        '-Wl,--start-group', '-lsgx_tstdc', '-lsgx_tcrypto', '-lsgx_tservice_sim', '-Wl,--end-group',
        '-Wl,-Bstatic', '-Wl,-Bsymbolic', '-Wl,-pie,-eenclave_entry', '-Wl,--export-dynamic',
        '-Wl,--defsym,__ImageBase=0', '-Wl,--gc-sections', '-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'), '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds')]
    run(key+'-link', link_command)
    ownership_audit(image, [app], trusted, linkmap)
    run(key+'-link-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK,
                         '--pinned', PINNED, '--link-map', linkmap])
    symbols = {int(w[0],16):w[2] for line in subprocess.check_output(
        ['nm','--defined-only',str(image)],text=True).splitlines()
               if len(w:=line.split()) == 3 and w[1] in ('t','T')}
    init = initializers(image) if profile == 'BASELINE' else audit(image)
    names = [symbols[v] for v in init['targets']]
    tail = names if profile == 'BASELINE' else names[1:]
    if tail_names is None:
        tail_names = tail
    assert tail == tail_names and tail[:2] == ['first_observer','second_observer'], names
    private_key = out/'test-key.pem'
    run(key+'-key', ['openssl','genrsa','-out',private_key,'-3','3072'])
    template = ROOT/'sdk/enclave.config.tmpl.xml'
    sizing = out/'sizing.xml'
    run(key+'-sizing-config', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config',
        '--template',template,'--base',base,'--size','0x40000000','--out',sizing])
    signed = out/'enclave.signed.so'
    run(key+'-sizing-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,
        '-enclave',image,'-out',out/'sizing.so','-config',sizing])
    extent = run(key+'-extent', ['python3', ROOT/'tools/sgx_metadata.py','required','--signed',out/'sizing.so']).stdout.strip()
    final = out/'final.xml'
    run(key+'-final-config', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config',
        '--template',template,'--base',base,'--size',extent,'--out',final])
    run(key+'-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,
        '-enclave',image,'-out',signed,'-config',final])
    run(key+'-metadata', ['python3',ROOT/'tools/sgx_metadata.py','verify','--signed',signed,'--base',base,'--size',extent])
    if profile != 'BASELINE':
        assert audit(signed) == init
    host = out/'host'
    run(key+'-host', ['gcc','-g','-O2','-I'+str(g),'-I'+str(SDK/'include'),
        HERE/'host.c',g/'probe_u.c','-o',host,'-L'+str(libraries),
        '-Wl,-rpath-link,'+str(libraries),'-lsgx_urts_sim','-lpthread'])
    env = dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(libraries),ENCBOUND_TEST_BASE=base)
    p = run(key+'-run', [host,signed], env=env)
    assert 'EARLY BOOTSTRAP SDK SIM PASS' in p.stdout
    rows.append(dict(mode='SDK SIM', profile=profile, base=base, result='pass',
        ecalls=18, startup_nested_entry='SDK ECALL_NOT_ALLOWED', initializers=names,
        image_sha256=digest(signed), application_unit=unit,
        linkmap_sha256=digest(linkmap),
        trusted_objects={str(p):digest(p) for p in trusted},
        application_object_sha256=digest(app),
        ownership_manifest_sha256=digest(Path(str(app)+'.ownership.json')),
        boundary_manifest_sha256=digest(g/'boundary-manifest.json')))
    print(key, 'PASS', flush=True)
    if profile != 'BASELINE' and base == '0x40000000':
        controls = []
        injection = out/'init_failure.o'
        run(key+'-failure-compile', ['gcc', *flags, '-c', HERE/'init_failure.c', '-o', injection])
        controls.append(('init-failure', app, [injection, '-Wl,--wrap=encbound_runtime_init']))
        fault = out/'fault.o'
        run(key+'-fault-app', [ROOT/'tools/with-integration-defaults.sh',ROOT/'tools/encbound-cc.sh',
            HERE/'app.c',fault,*flags,'-fno-common','-fno-builtin','-DSTARTUP_FAULT'],env=appenv)
        run(key+'-fault-place', [ROOT/'tools/with-integration-defaults.sh','python3',
            ROOT/'tools/mark_app_globals.py',fault,placed])
        placed.replace(fault)
        Path(str(placed)+'.ownership.json').replace(Path(str(fault)+'.ownership.json'))
        controls.append(('startup-range', fault, []))
        for case, application, extra in controls:
            bad_image = out/(case+'.so')
            bad_map = out/(case+'.map')
            command = [application if x == app else bad_image if x == image else
                       '-Wl,-Map,'+str(bad_map) if x == '-Wl,-Map,'+str(linkmap) else x
                       for x in link_command]
            run(key+'-'+case+'-link', [*command,*extra])
            ownership_audit(bad_image,[application],trusted+([injection] if extra else []),bad_map)
            audit(bad_image)
            bad_signed = out/(case+'.signed.so')
            run(key+'-'+case+'-sign', [SDK/'bin/x64/sgx_sign','sign','-key',private_key,
                '-enclave',bad_image,'-out',bad_signed,'-config',final])
            p = run(key+'-'+case+'-run',[host,bad_signed],env=env,expected=-4)
            assert not p.stdout
            rows.append(dict(mode='SDK SIM termination control',profile=profile,case=case,
                image_sha256=digest(bad_signed),result='SIGILL; attribution pending attribute.py'))

# Bootstrap alone does not admit application constructor metadata.
rejected = BUILD/'unsupported-ctor.c'
rejected.write_text('int g; __attribute__((constructor)) static void f(void){g=1;}\n')
p = run('unsupported-ctor',[ROOT/'tools/with-integration-defaults.sh','env','ENCBOUND_CXX_LIFECYCLE=0',ROOT/'tools/encbound-cc.sh',
    rejected,BUILD/'unsupported-ctor.o','-O2','-fno-common'],
    env=dict(os.environ,ENCBOUND_PROFILE='MAC27'),expected=None)
assert p.returncode and 'unsupported application constructor/destructor' in p.stderr, p.stderr
rows.append(dict(mode='compiler admission',case='application-startup-list-still-rejected',result='pass'))

inputs = [ROOT/'sdk/early_bootstrap.c',ROOT/'sdk/boundary_support.c',ROOT/'sdk/platform_layout.c',
          ROOT/'sdk/enclave.lds',ROOT/'sdk/enclave_sections.lds',ROOT/'sdk/enclave.config.tmpl.xml',
          ROOT/'config/integration.env',ROOT/'build/pass/encbound_pass.so',
          ROOT/'build/edger8r/sgx_edger8r',interface,
          *sorted((ROOT/'tools').glob('*.py')), *sorted((ROOT/'runtime').glob('*.[ch]')),
          *sorted((ROOT/'include').glob('*.h')), *sorted((ROOT/'sdk').glob('*.h')),
          *sorted(HERE.glob('*.*'))]
(BUILD/'results.json').write_text(json.dumps(dict(rows=rows, source_hashes={
    str(p):digest(p) for p in inputs if p.is_file()}), indent=2)+'\n')
print('EARLY BOOTSTRAP: native controls and four matched SDK SIM rows PASS')
