#!/usr/bin/env python3
"""SDK-owned RA import admission and real emitted-bridge native execution.

The native SDK functions are transport spies; this does not execute SDK RA.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
BUILD = ROOT/'build/integration/sdk-ecalls'
FIXTURE = ROOT/'tests/fixtures/sdk_ecalls'
CONTRACT = json.loads((ROOT/'tools/edger8r/sdk-ecalls.json').read_text())['sgx_tkey_exchange.edl']
SDK_NAMES = set(CONTRACT['symbols'])
POLICY = {'records': {}, 'sdk_only_imports': {'sgx_tkey_exchange.edl': {
    'domain': 'sdk', 'sha256': CONTRACT['sha256'], 'symbols': CONTRACT['symbols']}}}
EDL = '''enclave {
 include "sgx_tkey_exchange.h"
 from "sgx_tkey_exchange.edl" import *;
 trusted { public int application([in,out,size=n] uint8_t *p, size_t n); };
 untrusted { void observe([user_check] void *value); };
};
'''
SDK_ONLY = '''enclave {
 include "sgx_tkey_exchange.h"
 from "sgx_tkey_exchange.edl" import *;
};
'''
rows = []


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def run(command, log, *, env=None, diagnostic=None):
    command = list(map(str, command))
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    log.write_text(result.stdout+result.stderr)
    rows.append({'command': command, 'returncode': result.returncode,
                 'log': str(log), 'log_sha256': sha(log), 'expected_diagnostic': diagnostic})
    if diagnostic is None:
        assert result.returncode == 0, (command, log.read_text())
    else:
        assert result.returncode and diagnostic in log.read_text(), (command, log.read_text())
    return result


def generate(name, profile='MAC27', *, source=EDL, policy=None, files=None, eh=False, diagnostic=None):
    work = BUILD/name
    work.mkdir(parents=True, exist_ok=True)
    (work/'probe.edl').write_text(source)
    (work/'interface.json').write_text(json.dumps(POLICY if policy is None else policy, indent=2)+'\n')
    for filename, data in (files or {}).items():
        (work/filename).write_text(data)
    out = work/'generated'
    out.mkdir(exist_ok=True)
    for p in out.iterdir():
        p.unlink()
    flags = ['-I'+str(p) for p in (work, SDK/'include', ROOT/'sdk', ROOT/'include',
                                  ROOT/'tests/fixtures/modified_bridge')]
    command = ['python3', ROOT/'tools/modified_bridge.py', '--edl', work/'probe.edl',
               '--interface', work/'interface.json', '--generator', ROOT/'build/edger8r/sgx_edger8r',
               '--out-dir', out, '--profile', profile, '--search-path', work,
               '--search-path', SDK/'include', *['--cflag='+f for f in flags]]
    if eh:
        command += ['--cxx-eh']
    run(command, work/'generate.log', diagnostic=diagnostic)
    if diagnostic:
        assert not list(out.iterdir()), 'rejected EDL published artifacts'
        return work, out
    manifest = json.loads((out/'boundary-manifest.json').read_text())
    expected_sdk = SDK_NAMES if 'import *;' in source else {'sgx_ra_get_ga'}
    expected_app = {'application'} if 'public int application' in source else set()
    assert set(manifest['sdk_ecalls']) == expected_sdk
    assert set(manifest['application_ecalls']) == expected_app
    assert set(manifest['ecalls']) == expected_sdk | expected_app
    assert manifest['sdk_ecall_imports'] == ['sgx_tkey_exchange.edl']
    assert not SDK_NAMES & set(manifest['application_definitions']+manifest['eh_entries'])
    assert not SDK_NAMES & set((out/'admitted-app.txt').read_text().split())
    assert manifest['eh_entries'] == (['application'] if eh and expected_app else [])
    assert sha(ROOT/'tools/edger8r/sdk-ecalls.json') == manifest['inputs'][str(ROOT/'tools/edger8r/sdk-ecalls.json')]
    bridge = (out/'probe_t.c').read_text()
    for symbol in expected_sdk:
        body = bridge.split('static sgx_status_t SGX_CDECL sgx_'+symbol+'(void* pms)', 1)[1].split('\n}\n', 1)[0]
        assert '_encbound_cap_' not in body and '__encbound_eh_entry_' not in body
        assert ('encbound_bridge_enter()' in body) == (profile != 'BASELINE')
        assert ('encbound_boundary_release()' in body) == (profile != 'BASELINE')
    if profile == 'BASELINE' and not eh:
        stock = work/'stock'
        stock.mkdir(exist_ok=True)
        run([SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock, '--untrusted',
             '--untrusted-dir', stock, '--search-path', work, '--search-path', SDK/'include', work/'probe.edl'], work/'stock.log')
        for suffix in ('_t.c', '_t.h', '_u.c', '_u.h'):
            assert (out/('probe'+suffix)).read_bytes() == (stock/('probe'+suffix)).read_bytes()
    return work, out


def execute(work, out, profile, opt, sdk_only=False):
    app = work/('application-'+opt[1:]+'.o')
    flags = ['-I'+str(p) for p in (out, ROOT/'include', ROOT/'runtime', ROOT/'sdk',
                                  ROOT/'tests', ROOT/'tests/fixtures/modified_bridge', SDK/'include')]
    if not sdk_only:
        admitted = work/'admitted.txt'
        admitted.write_text('application\nobserve\n')
        env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted))
        run([ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
             FIXTURE/'application.c', app, opt, '-fno-common', '-fno-builtin',
             '-fno-vectorize', '-fno-slp-vectorize', *flags], work/('compile-'+opt[1:]+'.log'), env=env)
    sources = [FIXTURE/'native.c', ROOT/'tests/fake_platform.c', ROOT/'sdk/boundary_support.c']
    sources += [ROOT/'runtime'/n for n in ('siphash.c', 'runtime.c', 'capability.c', 'allocations.c', 'allocator.c', 'adapters.c')]
    command = ['clang-21', opt, '-g', '-Wall', '-Wextra', '-Wno-unused-parameter', *flags]
    if profile != 'BASELINE':
        command += ['-DENCBOUND_PROTECTED']
    if profile == 'MAC27':
        command += ['-DENCBOUND_MAC27']
    if sdk_only:
        command += ['-DSDK_ONLY']
    exe = work/('native-'+opt[1:])
    run([*command, *sources, *([] if sdk_only else [app]), '-Wl,--wrap=encbound_platform_init', '-o', exe], work/('link-'+opt[1:]+'.log'))
    run([exe], work/('run-'+opt[1:]+'.log'))


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    assert sha(SDK/'include/sgx_tkey_exchange.edl') == CONTRACT['sha256']
    run(['make', '-C', ROOT/'tools/edger8r'], BUILD/'build-generator.log')
    run(['make', '-C', ROOT/'pass'], BUILD/'build-pass.log')
    for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
        for sdk_only, source in ((False, EDL), (True, SDK_ONLY)):
            work, out = generate(('sdk-only-' if sdk_only else 'mixed-')+profile, profile, source=source)
            for opt in ('-O0', '-O2'):
                execute(work, out, profile, opt, sdk_only)
            generate(('eh-sdk-only-' if sdk_only else 'eh-mixed-')+profile, profile, source=source, eh=True)
        generate('selective-'+profile, profile, source=EDL.replace('import *;', 'import sgx_ra_get_ga;'))
    for key, value in (('sha256', '0'*64), ('domain', 'application'), ('symbols', [])):
        policy = copy.deepcopy(POLICY)
        policy['sdk_only_imports']['sgx_tkey_exchange.edl'][key] = value
        generate('bad-'+key, policy=policy, diagnostic='SDK import identity')
    sdk_source = (SDK/'include/sgx_tkey_exchange.edl').read_text()
    altered = sdk_source.replace('public sgx_status_t sgx_ra_get_ga', 'public sgx_status_t changed_ra_get_ga')
    policy = copy.deepcopy(POLICY)
    policy['sdk_only_imports']['sgx_tkey_exchange.edl'].update(
        sha256=hashlib.sha256(altered.encode()).hexdigest(),
        symbols=[n.replace('sgx_ra_get_ga', 'changed_ra_get_ga') for n in CONTRACT['symbols']])
    generate('self-consistent-substitution', policy=policy, files={'sgx_tkey_exchange.edl': altered}, diagnostic='SDK import identity')
    policy = copy.deepcopy(POLICY)
    policy['sdk_only_imports']['arbitrary.edl'] = policy['sdk_only_imports'].pop('sgx_tkey_exchange.edl')
    generate('unknown-trusted-contract', source=EDL.replace('sgx_tkey_exchange.edl', 'arbitrary.edl'),
             policy=policy, files={'arbitrary.edl': sdk_source}, diagnostic='SDK import identity')
    generate('application-domain-alias', source=EDL.replace(' trusted {', ' from "alias.edl" import *;\n trusted {'),
             files={'alias.edl': sdk_source}, diagnostic='application ECALL shadows SDK import')
    for kind, declaration in (('ECALL', 'trusted { public int sgx_ra_get_msg3_trusted(); };'),
                              ('OCALL', 'untrusted { int sgx_ra_get_msg3_trusted(); };')):
        generate('unselected-shadow-'+kind, source=EDL.replace('import *;', 'import sgx_ra_get_ga;').replace(
            ' trusted {', ' from "shadow.edl" import *;\n trusted {'),
            files={'shadow.edl': 'enclave { '+declaration+' };'}, diagnostic='application '+kind+' shadows SDK import')
    raw = BUILD/'raw.c'
    raw.write_text('#include <sgx_tkey_exchange.h>\nsgx_status_t raw(sgx_ra_context_t c, sgx_ec256_public_t *p) { return sgx_ra_get_ga(c,p); }\n')
    env = dict(os.environ, ENCBOUND_PROFILE='MAC27')
    run([ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh', raw, BUILD/'raw.o',
         '-O2', '-I'+str(SDK/'include')], BUILD/'reject-raw-application-call.log', env=env,
        diagnostic='sgx_ra_get_ga')
    record = {'scope': 'native generation/admission and transport-spy execution; no real SDK RA or SGX isolation',
              'rows': rows, 'inputs': {str(p): sha(p) for p in
              [Path(__file__), FIXTURE/'native.c', FIXTURE/'application.c', ROOT/'tools/edger8r/sdk-ecalls.json']}}
    (BUILD/'results.json').write_text(json.dumps(record, indent=2)+'\n')
    print('SDK ECALLS PASS: 12 native O0/O2 execution rows, mixed/SDK-only/EH/selective imports and ownership negatives')


if __name__ == '__main__':
    main()
