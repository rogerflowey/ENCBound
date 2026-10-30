#!/usr/bin/env python3
"""Native application imports, SDK ownership, selection and dependency controls.

Bridge execution with real instrumentation is in edl_buffers_test.py
--application-imports. These cases exercise admission and emitted ABI metadata.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
BUILD = ROOT/'build/integration/edl-imports'
GEN = ROOT/'build/edger8r/sgx_edger8r'
BUILD.mkdir(parents=True, exist_ok=True)
rows = []
POLICY = json.loads((ROOT/'tests/fixtures/wallet/boundary-interface.json').read_text())
POLICY['records'] = {'Big': {'header': 'types.h'}}
SOURCE = '''enclave {
 from "api.edl" import *;
 from "sgx_tstdc.edl" import sgx_oc_cpuidex;
 trusted { public int root_entry(); };
};
'''
API = '''enclave {
 from "leaf.edl" import *;
 include "types.h"
 trusted {
 #include "api_body.edlinc"
 };
 untrusted { int emit([in,out,count=n] int *data, size_t n); };
};
'''
FILES = {
    'imports.edl': SOURCE,
    'api.edl': API,
    'leaf.edl': 'enclave { trusted { public int leaf(); }; untrusted { void leaf_event(); }; };\n',
    'api_body.edlinc': '''public int imported([in,out,count=n] int *data, size_t n);
public int value(Big b);
''',
    'types.h': '#include <stdint.h>\ntypedef struct Big { uint64_t words[8]; } Big;\n',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log):
    command = list(map(str, command))
    p = subprocess.run(command, text=True, capture_output=True, timeout=60)
    log.write_text(p.stdout+p.stderr)
    return p, dict(command=command, returncode=p.returncode, log=str(log), log_sha256=sha(log))


def case(name, profile='MAC27', changes=None, policy=None, diagnostic=None, eh=False,
         ecalls=None, ocalls=None):
    work = BUILD/name
    work.mkdir(exist_ok=True)
    files = {**FILES, **(changes or {})}
    for filename, contents in files.items():
        (work/filename).write_text(contents)
    config = work/'interface.json'
    config.write_text(json.dumps(POLICY if policy is None else policy, indent=2)+'\n')
    out = work/'generated'
    # A previously successful case must not mask rejected publication on rerun.
    if out.exists():
        for file in out.iterdir():
            file.unlink()
    flags = ['-I'+str(p) for p in (work, SDK/'include', ROOT/'sdk', ROOT/'include',
                                  ROOT/'tests/fixtures/modified_bridge')]
    command = ['python3', ROOT/'tools/modified_bridge.py', '--edl', work/'imports.edl',
               '--interface', config, '--generator', GEN, '--profile', profile, '--out-dir', out,
               '--search-path', work, '--search-path', SDK/'include',
               *['--cflag='+f for f in flags]]
    if eh:
        command += ['--cxx-eh']
    p, record = run(command, work/'generate.log')
    record.update(name=name, profile=profile, cxx_eh=eh, expected_success=diagnostic is None)
    rows.append(record)
    if diagnostic is not None:
        assert p.returncode and diagnostic in p.stdout+p.stderr, (name, p.stdout+p.stderr)
        assert not list(out.iterdir()), 'rejected EDL published output'
        return work, out
    assert p.returncode == 0, (name, p.stdout+p.stderr)
    manifest = json.loads((out/'boundary-manifest.json').read_text())
    native = json.loads((out/'edger8r-admission.json').read_text())
    assert manifest['imports'] == native['imports']
    assert set(native['ecalls']) == set(ecalls or ['root_entry', 'imported', 'value', 'leaf'])
    assert set(native['ocalls']) == set(ocalls or ['emit', 'leaf_event'])
    assert (out/'admitted-ocalls.txt').read_text().splitlines() == native['trusted_ocalls']
    for origin in native['imports']:
        path = Path(origin['path'])
        assert origin['sha256'] == manifest['inputs'][str(path)] == sha(path)
        assert str(path) in (out/'boundary.d').read_text()
        if origin['domain'] == 'sdk':
            assert not origin['declared_ecalls']
            assert set(origin['declared_ocalls']) <= set(native['sdk_only'])
        else:
            assert origin['domain'] == 'application'
            assert not set(origin['declared_ocalls']) & set(native['sdk_only'])
    for filename in ('imports.edl', 'types.h', 'api_body.edlinc'):
        assert manifest['inputs'][str(work/filename)] == sha(work/filename)
    if eh:
        expected = [
            '__encbound_edl_app_value' if n == 'value' and profile != 'BASELINE' else n
            for n in native['ecalls']]
        assert native['eh_entries'] == expected
        assert (out/'eh-entries.txt').read_text().splitlines() == expected
        bridge = (out/'imports_t.c').read_text()
        for entry in expected:
            assert '__encbound_eh_entry_'+entry in bridge
    if profile != 'BASELINE' and 'value' in native['ecalls']:
        assert '__encbound_edl_app_value' in native['application_definitions']
        assert 'const Big* _encbound_record_b' in (out/'imports_app.h').read_text()
    if profile == 'BASELINE' and not eh:
        stock = work/'stock'
        stock.mkdir(exist_ok=True)
        p, stock_record = run([SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock,
            '--untrusted', '--untrusted-dir', stock, '--search-path', work,
            '--search-path', SDK/'include', work/'imports.edl'], work/'stock.log')
        assert p.returncode == 0, p.stdout+p.stderr
        for suffix in ('_t.c', '_t.h', '_u.c', '_u.h'):
            assert (out/('imports'+suffix)).read_bytes() == (stock/('imports'+suffix)).read_bytes()
        record['stock'] = stock_record
    record['manifest_sha256'] = sha(out/'boundary-manifest.json')
    return work, out


for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    case('wildcard-'+profile, profile)
    case('eh-'+profile, profile, eh=True)
    case('selective-'+profile, profile,
         changes={'imports.edl': SOURCE.replace('import *;', 'import imported, emit, leaf, leaf_event;')},
         ecalls=['root_entry', 'imported', 'leaf'])
    case('repeated-'+profile, profile, changes={'imports.edl': SOURCE.replace(
         'from "api.edl" import *;', 'from "api.edl" import imported;\n from "api.edl" import value, emit;')},
         ecalls=['root_entry', 'imported', 'value'], ocalls=['emit'])
    case('diamond-'+profile, profile, changes={
         'imports.edl': SOURCE.replace('from "api.edl" import *;',
                                      'from "left.edl" import *;\n from "right.edl" import *;'),
         'left.edl': 'enclave { from "api.edl" import *; };\n',
         'right.edl': 'enclave { from "leaf.edl" import *; };\n'})
    case('nested-sdk-'+profile, profile, changes={
         'imports.edl': SOURCE.replace(' from "sgx_tstdc.edl" import sgx_oc_cpuidex;\n', ''),
         'api.edl': API.replace('enclave {', 'enclave { from "sgx_tstdc.edl" import sgx_oc_cpuidex;')})

policy = json.loads(json.dumps(POLICY))
policy['sdk_only_imports'] = {}
case('application-only', changes={'imports.edl': SOURCE.replace(
     ' from "sgx_tstdc.edl" import sgx_oc_cpuidex;\n', '')}, policy=policy)

for name, old, new in (
    ('private-ecall', 'public int imported', 'int imported'),
    ('unknown-type', 'public int imported', 'public Unknown imported'),
):
    case(name, changes={'api_body.edlinc': FILES['api_body.edlinc'].replace(old, new)}, diagnostic='ENCBound:')
case('pointer-bearing-record', changes={'types.h': FILES['types.h'].replace('words[8]', '*words')}, diagnostic='ENCBound:')
case('pointer-result', changes={'api_body.edlinc': FILES['api_body.edlinc'].replace('public int imported', 'public char *imported')})
case('shallow-pointer-array', changes={'api_body.edlinc': FILES['api_body.edlinc'].replace('int *data', 'int **data')})
case('pointer-imported-ocall', changes={'api.edl': API.replace(
     'int emit([in,out,count=n] int *data, size_t n);', 'void *emit();')})
case('reentrant-imported-ocall', changes={'api.edl': API.replace(
     'size_t n); };', 'size_t n) allow(imported); };')}, diagnostic='unsupported OCALL mode')
case('missing-import', changes={'api.edl': API.replace('leaf.edl', 'absent.edl')}, diagnostic='File not found')
case('missing-selection', changes={'imports.edl': SOURCE.replace('import *;', 'import absent;')}, diagnostic='import failed')
case('cycle', changes={'leaf.edl': 'enclave { from "api.edl" import *; };'}, diagnostic='circled import')
case('duplicate-selected', changes={'leaf.edl': FILES['leaf.edl'].replace('int leaf()', 'int root_entry()')}, diagnostic='Multiple definition')

# Check every application origin before Intel's selective-import filtering.
# The SDK name here is deliberately unselected from sgx_tstdc.edl.
shadow = 'sgx_thread_wait_untrusted_event_ocall'
for kind, declaration in (
    ('ocall', 'untrusted { int '+shadow+'([user_check] void *p); };'),
    ('ecall', 'trusted { public int '+shadow+'(); };'),
):
    for order in ('before', 'after'):
        root = SOURCE.replace('from "api.edl" import *;', 'from "api.edl" import imported;')
        if order == 'before':
            root = root.replace(' from "api.edl" import imported;\n', '')
            root = root.replace(' trusted {', ' from "api.edl" import imported;\n trusted {')
        case('shadow-'+kind+'-'+order, changes={
             'imports.edl': root, 'leaf.edl': 'enclave { '+declaration+' };'},
             diagnostic='application '+kind.upper()+' shadows SDK import')

for key, value in (('sha256', '0'*64), ('domain', 'application'), ('symbols', [])):
    policy = json.loads(json.dumps(POLICY))
    policy['sdk_only_imports']['sgx_tstdc.edl'][key] = value
    case('sdk-'+key, policy=policy, diagnostic='SDK import identity')
policy = json.loads(json.dumps(POLICY))
policy['sdk_only_imports']['api.edl'] = dict(domain='sdk', sha256=hashlib.sha256(API.encode()).hexdigest(),
                                          symbols=['imported', 'value', 'emit'])
case('application-as-sdk', policy=policy, diagnostic='SDK import identity')
policy = json.loads(json.dumps(POLICY))
policy['sdk_only_imports']['absent.edl'] = policy['sdk_only_imports']['sgx_tstdc.edl']
case('unused-sdk-policy', policy=policy, diagnostic='unused SDK import metadata')

# Reclassifying the same physical source via an import alias cannot bypass
# application ownership. Use a non-reserved SDK service name for this control.
sdk_source = 'enclave { untrusted { void platform_service([user_check] void *p); }; };\n'
policy = dict(records=POLICY['records'], sdk_only_imports={'platform.edl': dict(
    domain='sdk', sha256=hashlib.sha256(sdk_source.encode()).hexdigest(), symbols=['platform_service'])})
case('domain-alias', changes={
    'imports.edl': SOURCE.replace('from "sgx_tstdc.edl" import sgx_oc_cpuidex;',
        'from "platform.edl" import *;\n from "application_alias.edl" import *;'),
    'platform.edl': sdk_source, 'application_alias.edl': sdk_source}, policy=policy,
    diagnostic='application OCALL shadows SDK import')
policy['sdk_only_imports']['platform.edl']['sha256'] = hashlib.sha256(
    sdk_source.replace('enclave {', 'enclave { from "leaf.edl" import *;').encode()).hexdigest()
case('nested-sdk-rejected', changes={
    'imports.edl': SOURCE.replace('sgx_tstdc.edl', 'platform.edl').replace('import sgx_oc_cpuidex;', 'import *;'),
    'platform.edl': sdk_source.replace('enclave {', 'enclave { from "leaf.edl" import *;')},
    policy=policy, diagnostic='SDK import identity')

(BUILD/'results.json').write_text(json.dumps(dict(
    scope='native Intel AST admission and generation only', rows=rows), indent=2)+'\n')
print('APPLICATION EDL IMPORTS PASS:', len(rows), 'cases; native selection, provenance, stock equality, SDK ownership and EH/record entries')
