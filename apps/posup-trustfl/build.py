#!/usr/bin/env python3
"""Build a bounded required-ECALL integration; retain original-source diagnostics."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
from prepare import HERE, ROOT, PINS, SOURCES, prepare, sha

SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
SDK_SRC = Path(os.environ.get('PINNED_SRC', str(ROOT/'deps/intel-sgx')))
MAPPINGS = {'sgx_read_rand': 'encbound_usig_rand', 'sgx_hmac_sha256_msg': 'encbound_usig_hmac'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--app', choices=PINS, required=True)
    ap.add_argument('--profile', choices=('BASELINE', 'RADIX_ONLY', 'MAC27'), required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--source', type=Path)
    ap.add_argument('--base', choices=('0x40000000', '0x140000000'), default='0x40000000')
    args = ap.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out = args.out.resolve()
    if not out.is_relative_to(ROOT/'build') or out.exists():
        ap.error('use a fresh output directory under this repository build/')
    out.mkdir(parents=True)
    for name in ('objects', 'generated', 'enclave', 'logs'):
        (out/name).mkdir()
    record = dict(app=args.app, profile=args.profile, base=args.base, source=PINS[args.app], commands=[])

    def save():
        (out/'probe.json').write_text(json.dumps(record, indent=2)+'\n')

    def run(name, cmd, env=None, fail=True):
        cmd = list(map(str, cmd))
        proc = subprocess.run(cmd, env=env, cwd=ROOT, text=True, capture_output=True, timeout=600)
        log = out/'logs'/(name+'.log')
        log.write_text(proc.stdout+proc.stderr)
        row = dict(name=name, command=cmd, returncode=proc.returncode, log=str(log), sha256=sha(log))
        record['commands'].append(row)
        save()
        print(args.app, args.profile, name, 'PASS' if proc.returncode == 0 else 'FAIL', flush=True)
        if fail and proc.returncode:
            raise SystemExit((proc.stdout+proc.stderr)[-5000:]+'\nSee '+str(log))
        return proc

    prepared = prepare(args.app, out, args.source)
    record['prepared_record_sha256'] = sha(out/'prepared.json')
    p, g, e = out/'prepared', out/'generated', out/'enclave'
    env = dict(os.environ, ENCBOUND_PROFILE=args.profile, ENCBOUND_CXX_EH='0',
               ENCBOUND_KEEP_GEP_FLAGS='0', ENCBOUND_POST_INSTCOMBINE='0',
               ENCBOUND_PLUGIN=str(out/'toolchain/pass/encbound_pass.so'),
               ENCBOUND_LIBCXX_PREPARED=str(out/'libcxx-prepared'))
    wrap = [ROOT/'tools/with-integration-defaults.sh']
    run('pass', ['make', '-C', ROOT/'pass', 'BUILD='+str(out/'toolchain/pass')])
    run('generator', ['make', '-C', ROOT/'tools/edger8r', 'BUILD='+str(out/'toolchain/edger8r')])
    run('sdk-pins', ['python3', ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', SDK_SRC])
    includes = ['-I'+str(x) for x in (p, g, ROOT/'include', ROOT/'runtime', ROOT/'sdk',
                SDK/'include', SDK/'include/tlibc', SDK_SRC/'common/inc/internal')]
    common = ['-O2', '-g', '-fno-builtin', '-fno-common', '-nostdinc', '-fpie', '-fvisibility=hidden',
              '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong', *includes]
    interface = ROOT/'apps/conflow/boundary-interface.json'

    def bridge(edl, dest, extra=(), metadata=interface):
        search = [edl.parent, SDK/'include', *extra]
        return ['python3', ROOT/'tools/modified_bridge.py', '--edl', edl, '--interface', metadata,
                '--generator', out/'toolchain/edger8r/sgx_edger8r', '--out-dir', dest,
                '--profile', args.profile, '--layout-cc', 'clang-21',
                *[x for d in search for x in ('--search-path', d)],
                *['--cflag='+f for f in includes+['-I'+str(x) for x in extra]+['-nostdinc']]]

    source = Path(prepared['source'])
    original_edl = source/'Enclave/Enclave.edl'
    extra = [source/('include' if args.app == 'POSUP' else 'Include')]
    original_interface = out/'original-interface.json'
    original_interface.write_text(json.dumps(dict(records={}, sdk_only_imports={}))+'\n')
    original_metadata = interface if args.app == 'POSUP' else original_interface
    record['original_bridge_rc'] = run('original-bridge', bridge(original_edl, out/'original-generated', extra, original_metadata), fail=False).returncode
    run('selected-bridge', bridge(p/'Enclave.edl', g))
    caller = p/'Enclave.cpp'
    libraries = []
    if args.app == 'POSUP':
        run('libcxx-prepare', ['python3', ROOT/'apps/libcxx/prepare.py'], env)
        run('libcxx', [*wrap, 'python3', ROOT/'apps/libcxx/build.py', '--profile', args.profile,
                      '--out-dir', out/'libcxx', '--caller', caller,
                      *['--caller-flag='+f for f in includes]], env)
        lib = json.loads((out/'libcxx/build.json').read_text())
        flags = lib['flags']+includes+['-g', '-Dabs=app_posup_abs']
        libraries = list(map(Path, lib['objects']))
    else:
        # This selected C-style path uses no C++ runtime/header/library code.
        flags = common+['-std=c++17', '-fno-exceptions', '-fno-rtti', '-nostdinc++']
    definitions = set()
    frontend = out/'selected.frontend.ll'
    run('selected-inventory', ['clang-21', *flags, '-S', '-emit-llvm', caller, '-o', frontend])
    text = frontend.read_text()
    definitions.update(re.findall(r'^define .*?@([^ (]+)\(', text, re.M))
    definitions.update(re.findall(r'^@([^ ]+) = .*?alias ', text, re.M))
    admitted = out/'admitted.txt'
    inventory = '\n'.join(sorted(definitions))+'\n'+(g/'admitted-app.txt').read_text()+(g/'admitted-ocalls.txt').read_text()
    if libraries:
        inventory += (out/'libcxx/admitted.txt').read_text()
        # Select one pinned BSD libc unit as ordinary instrumented application
        # code. Private naming avoids interposition on the SDK's own abs.
        abs_source = SDK_SRC/'sdk/tlibc/stdlib/abs.c'
        assert sha(abs_source) == '9944dfff06f4776407cd08c09c6a57ece27581cf47d9b0c2a5342bdf50c4aa3c'
        inventory += 'app_posup_abs\n'
    if args.app == 'TrustFL':
        inventory += '\n'.join(n+' = '+v for n, v in MAPPINGS.items())+'\n'
    admitted.write_text(inventory)
    env['ENCBOUND_ADMITTED'] = str(admitted)
    record.update(adapter_mappings=MAPPINGS if args.app == 'TrustFL' else {}, frontend_flags=flags)

    # Diagnose the whole original required-entry unit independently. These
    # objects are never linked into the selected enclave.
    original_header_dir = out/'original-generated'
    original_flags = ['-I'+str(original_header_dir)]+list(flags)+['-I'+str(source/'Enclave'), *['-I'+str(x) for x in extra]]
    original = Path(prepared['original'])
    if args.app == 'POSUP':
        # Modern SDK port diagnostic: drop one obsolete, unused SDK include and
        # the C-only bool macro. Keep original bytes separately; no body changes.
        port = out/'original-port'
        for directory in ('Enclave', 'include'):
            shutil.copytree(source/directory, port/directory)
        conf = port/'include/conf.h'
        conf.write_text(conf.read_text().replace('#include "sgx_tae_service.h"', '/* obsolete unused sgx_tae_service.h include removed */'))
        unit = port/'Enclave/Enclave.cpp'
        unit.write_text(unit.read_text().replace('#define bool _Bool', '/* C-only bool macro removed for C++17 */'))
        record['original_port'] = dict(adaptations=['Remove obsolete unused sgx_tae_service.h include', 'Remove C-only bool macro in C++ source'],
            files={str(x):sha(x) for x in (conf, unit)})
        run('ported-original-bridge', bridge(port/'Enclave/Enclave.edl', original_header_dir,
            [port/'include'], interface), fail=False)
        original = unit
        original_flags = ['-I'+str(original_header_dir), '-I'+str(port/'include'), '-I'+str(port/'Enclave')]+list(flags)
    if args.app == 'TrustFL':
        # Headers use private libc++ for this diagnostic, rather than rejecting
        # iostream merely because the selected subset needs no STL.
        run('original-libcxx-prepare', ['python3', ROOT/'apps/libcxx/prepare.py'], env)
        original_flags = [f for f in original_flags if f != '-nostdinc++']+[
            '-nostdinc++', '-I'+str(out/'libcxx-prepared/headers'), '-I'+str(SDK/'include/libcxx'),
            *['-D'+n+'=app_libcxx_'+n for n in ('memchr', 'wmemcpy', 'wmemmove', 'wmemset', 'wmemchr', 'wmemcmp', 'wcslen')]]
    record['original_frontend_rc'] = run('original-frontend', ['clang-21', *original_flags,
        '-S', '-emit-llvm', original, '-o', out/'original.frontend.ll'], fail=False).returncode
    if record['original_frontend_rc'] == 0:
        original_text = (out/'original.frontend.ll').read_text()
        original_inventory = out/'original-admitted.txt'
        original_defs = set(re.findall(r'^define .*?@([^ (]+)\(', original_text, re.M))
        original_defs.update(re.findall(r'^@([^ ]+) = .*?alias ', original_text, re.M))
        original_inventory.write_text(inventory+'\n'.join(sorted(original_defs))+'\n')
        if args.app == 'POSUP':
            with original_inventory.open('a') as stream:
                stream.write('sgx_read_rand = encbound_usig_rand\n')
        original_env = dict(env, ENCBOUND_ADMITTED=str(original_inventory))
        record['original_application_rc'] = run('original-application', [*wrap, ROOT/'tools/encbound-cc.sh',
            original, out/'objects/original.o', *original_flags], original_env, fail=False).returncode
    if args.app == 'POSUP':
        primitive = out/'original-primitives.cpp'
        primitive.write_text('#include "'+str(source/'Enclave/oblivious-primitives.h')+'"\n')
        record['primitive_rc'] = run('original-primitives', [*wrap, ROOT/'tools/encbound-cc.sh', primitive,
            out/'objects/original-primitives.o', *common, '-std=c++17', '-fno-exceptions', '-fno-rtti', '-nostdinc++'], env, fail=False).returncode
    obj, placed = out/'objects/Enclave.o', e/'Enclave.o'
    run('selected-application', [*wrap, ROOT/'tools/encbound-cc.sh', caller, obj, *flags], env)
    run('selected-placement', [*wrap, ROOT/'tools/mark_appdata_sections.sh', obj, placed], env)
    record['admission_passed'] = True
    save()
    app = [placed]
    original_objects = [obj]
    if args.app == 'POSUP':
        abs_obj, abs_placed = out/'objects/abs.o', e/'abs.o'
        run('abs-application', [*wrap, ROOT/'tools/encbound-cc.sh', abs_source, abs_obj,
            *common, '-std=c99', '-Dabs=app_posup_abs'], env)
        run('abs-placement', [*wrap, ROOT/'tools/mark_appdata_sections.sh', abs_obj, abs_placed], env)
        app.append(abs_placed)
        original_objects.append(abs_obj)
    app += libraries
    original_objects += libraries
    # Required signatures have no by-value records: no generated app adapters.
    assert not (g/'Enclave_app.c').read_text().strip() or not re.search(r'\bvoid\s+\w+\s*\(', (g/'Enclave_app.c').read_text())
    trusted_sources = [g/'Enclave_t.c', ROOT/'runtime/cxx_allocations.c', ROOT/'runtime/cxx_services.c']
    defines = ['-DENCBOUND_CXX_BASELINE'] if args.profile == 'BASELINE' else ['-DENCBOUND_PROTECTED']
    if args.profile != 'BASELINE':
        trusted_sources = [ROOT/'sdk/early_bootstrap.c', *trusted_sources,
            ROOT/'sdk/boundary_support.c', ROOT/'sdk/platform_layout.c',
            *[ROOT/'runtime'/(n+'.c') for n in ('check_core', 'allocations', 'allocator', 'adapters', 'cxx_lifecycle')]]
        if args.app == 'TrustFL':
            # Reuse the already tested exact contracts; no raw name allowlist.
            trusted_sources += [ROOT/'apps/go-consensus-usig/adapters.c']
    if args.profile == 'MAC27':
        defines += ['-DENCBOUND_MAC27']
    trusted, trusted_units = [], []
    for i, src in enumerate(trusted_sources):
        target = e/f'trusted-{i}-{src.stem}.o'
        run('trusted-'+str(i), ['clang-21', *common, *defines, '-MMD', '-MF', target.with_suffix('.d'), '-c', src, '-o', target])
        deps = shlex.split(target.with_suffix('.d').read_text().replace('\\\n', ' ').partition(':')[2])
        trusted_units.append(dict(object=str(target), sha256=sha(target), inputs={str(Path(d).resolve()): sha(d) for d in deps}))
        trusted.append(target)
    image, signed = e/'enclave.so', e/'enclave.signed.so'
    run('link', ['clang-21', *trusted, *app, '-o', image, '-nostdlib', '-nodefaultlibs', '-nostartfiles', '-L'+str(SDK/'lib64'),
        '-Wl,--whole-archive', '-lsgx_trts_sim', '-Wl,--no-whole-archive', '-Wl,--start-group',
        '-lsgx_tcxx', '-lsgx_tstdc', '-lsgx_tcrypto', '-lsgx_tservice_sim', '-Wl,--end-group',
        '-Wl,-Bstatic,-Bsymbolic,--no-undefined,-pie,-eenclave_entry,--export-dynamic,--defsym,__ImageBase=0',
        '-Wl,-z,relro,-z,now,-z,noexecstack,--gc-sections', '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),
        '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'), '-Wl,-Map,'+str(e/'enclave.map')])
    key = out/'test-key.pem'
    run('key', ['openssl', 'genrsa', '-out', key, '-3', '3072'])
    extent = '0x40000000'
    for stage in ('sizing', 'final'):
        cfg = out/(stage+'.xml')
        dest = out/'sizing.so' if stage == 'sizing' else signed
        run(stage+'-config', ['python3', ROOT/'tools/sgx_metadata.py', 'render-config', '--template',
            ROOT/'apps/go-consensus-usig/enclave.config.tmpl.xml', '--base', args.base, '--size', extent, '--out', cfg])
        run(stage+'-sign', [SDK/'bin/x64/sgx_sign', 'sign', '-key', key, '-enclave', image, '-out', dest, '-config', cfg])
        if stage == 'sizing':
            extent = run('extent', ['python3', ROOT/'tools/sgx_metadata.py', 'required', '--signed', dest]).stdout.strip()
    run('metadata', ['python3', ROOT/'tools/sgx_metadata.py', 'verify', '--signed', signed, '--base', args.base, '--size', extent])
    host = out/'host'
    run('host', ['cc', '-O2', '-g', '-Wno-deprecated-declarations', '-DAPP_'+args.app.upper(), '-I'+str(p), '-I'+str(g),
        '-I'+str(SDK/'include'), HERE/'host.c', g/'Enclave_u.c', '-L'+str(SDK/'lib64'),
        '-Wl,-rpath-link,'+str(SDK/'lib64'), '-lsgx_urts_sim', '-lpthread', '-lcrypto', '-o', host])
    build = dict(app=args.app, profile=args.profile, base=args.base, extent=extent,
        app_objects=list(map(str, app)), original_objects=list(map(str, original_objects)),
        trusted_objects=list(map(str, trusted)), trusted_units=trusted_units,
        image=str(image), signed=str(signed), host=str(host),
        inputs={str(x): sha(x) for x in [HERE/'build.py', HERE/'prepare.py', HERE/'audit.py', HERE/'host.c',
            ROOT/'apps/four_app_permissions.h', ROOT/'apps/go-consensus-usig/adapters.c',
            ROOT/'apps/go-consensus-usig/enclave.config.tmpl.xml', ROOT/'sdk/enclave.lds', ROOT/'sdk/enclave_sections.lds',
            ROOT/'tools/audit_app_globals.py', ROOT/'config/integration.env', Path(env['ENCBOUND_PLUGIN']),
            out/'toolchain/edger8r/sgx_edger8r']},
        artifacts={str(x): sha(x) for x in app+trusted+[image, signed, host, e/'enclave.map', out/'final.xml']})
    (out/'build.json').write_text(json.dumps(build, indent=2)+'\n')
    run('audit', ['python3', HERE/'audit.py', '--build', out])
    run('functional', [host, signed], dict(os.environ, LD_LIBRARY_PATH=str(SDK/'lib64'), ENCBOUND_TEST_BASE=args.base))


if __name__ == '__main__':
    main()
