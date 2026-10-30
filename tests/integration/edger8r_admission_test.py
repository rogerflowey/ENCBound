#!/usr/bin/env python3
"""Native Intel-AST admission, C layout, dependency and stock-output regressions."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
BUILD = ROOT/'build/integration/edger8r-admission'
GEN = ROOT/'build/edger8r/sgx_edger8r'
BUILD.mkdir(parents=True, exist_ok=True)
rows = []

with tempfile.TemporaryDirectory(dir=BUILD) as temp:
    work = Path(temp)
    header = work/'types.h'
    types = '''#include <stdbool.h>
#include <stdint.h>
typedef struct Inner { bool enabled; double ratio; } Inner;
typedef struct Packet { Inner values[2]; uint32_t sequence; } Packet;
'''
    header.write_text(types)
    fragment = work/'entry.edlinc'
    fragment.write_text('''public int run(Inner small, [in,count=1] Packet *value, [in,string] char *text,
        [in,out,count=n] uint32_t *words, size_t n,
        [out,size=1] bool *ok, double number);
''')
    source = work/'sample.edl'
    edl = '''enclave {
 from "sgx_tstdc.edl" import *;
 include "types.h"
 trusted {
 #include "entry.edlinc"
 };
 untrusted {
  int emit([in,out,size=8] char *prefix, [in,count=n] uint32_t *words, size_t n);
  double measure(float value);
 };
};
'''
    source.write_text(edl)
    policy = json.loads((ROOT/'apps/libc-format/boundary-interface.json').read_text())
    policy['records'] = {'Packet': {'header': 'types.h'}, 'Inner': {'header': 'types.h'}}
    config = work/'interface.json'
    config.write_text(json.dumps(policy))
    flags = ['-I'+str(p) for p in (work, SDK/'include', ROOT/'sdk', ROOT/'include',
                                  ROOT/'tests/fixtures/modified_bridge')]

    def generate(name, profile='MAC27', success=True, diagnostic=''):
        out = work/name
        cmd = ['python3', ROOT/'tools/modified_bridge.py', '--wide-scalars',
               '--edl', source, '--interface', config, '--generator', GEN,
               '--profile', profile, '--out-dir', out, '--search-path', SDK/'include']
        cmd += ['--cflag='+f for f in flags]
        result = subprocess.run(list(map(str, cmd)), text=True, capture_output=True)
        log = BUILD/(name+'.log')
        log.write_text(result.stdout+result.stderr)
        rows.append(dict(name=name, profile=profile, expected_success=success,
                         returncode=result.returncode, log=str(log)))
        assert (result.returncode == 0) == success, log.read_text()
        if not success:
            assert diagnostic in log.read_text(), log.read_text()
            assert not list(out.glob('*_t.c')), 'rejected source published bridge'
        return out

    for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
        out = generate(profile, profile)
        native = json.loads((out/'edger8r-admission.json').read_text())
        assert native['ecalls'] == ['run'] and native['ocalls'] == ['emit','measure']
        manifest = json.loads((out/'boundary-manifest.json').read_text())
        for dependency in (source, header, fragment, SDK/'include/sgx_tstdc.edl'):
            assert manifest['inputs'][str(dependency)] == hashlib.sha256(dependency.read_bytes()).hexdigest()
        assert 'encbound_edl.py' not in json.dumps(manifest)
        assert 'record offset' in (out/'bridge-abi.c').read_text()
        # Run emitted proxies with the real checked runtime; the SDK SIM
        # formatter fixture separately executes instrumented application code.
        runtime = [ROOT/'runtime'/n for n in ('siphash.c','runtime.c','capability.c',
                    'allocations.c','allocator.c','adapters.c')]
        executable = out/'buffer-native'
        # This fixture exercises OCALLs only. The record suite separately links
        # and executes the generated application side of each ECALL adapter.
        cmd = ['clang-21','-O1','-ffunction-sections','-fdata-sections','-Wl,--gc-sections',*flags,'-I'+str(out),'-I'+str(ROOT/'runtime'),
               '-I'+str(ROOT/'tests')]
        if profile != 'BASELINE': cmd += ['-DENCBOUND_PROTECTED']
        if profile == 'MAC27': cmd += ['-DENCBOUND_MAC27']
        cmd += [ROOT/'tests/fixtures/modified_bridge/buffer_native.c',
                ROOT/'tests/fake_platform.c',ROOT/'sdk/boundary_support.c',
                *runtime,'-o',executable]
        subprocess.run(list(map(str,cmd)), check=True, capture_output=True)
        subprocess.run([executable], check=True, capture_output=True)
        if profile == 'BASELINE':
            stock = work/'stock'; stock.mkdir()
            subprocess.run(list(map(str, [SDK/'bin/x64/sgx_edger8r', '--trusted',
                '--trusted-dir', stock, '--untrusted', '--untrusted-dir', stock,
                '--search-path', SDK/'include', source])), check=True, capture_output=True)
            for suffix in ('_t.c','_t.h','_u.c','_u.h'):
                assert (stock/('sample'+suffix)).read_bytes() == (out/('sample'+suffix)).read_bytes()

    variants = {
        'pointer-member': ('uint32_t sequence;', 'uint32_t *sequence;'),
        'nested-pointer': ('double ratio;', 'double *ratio;'),
        'bitfield': ('uint32_t sequence;', 'uint32_t sequence:2;'),
        'flexible-array': ('uint32_t sequence;', 'uint32_t sequence[];'),
        'packed': ('struct Packet {', 'struct __attribute__((packed)) Packet {'),
        'union': ('struct Packet {', 'union Packet {'),
    }
    for name, (old, new) in variants.items():
        header.write_text(types.replace(old, new))
        generate(name, success=False, diagnostic='ENCBound:')
    header.write_text('typedef void *ssize_t;\n'+types.replace('uint32_t sequence;', 'ssize_t sequence;'))
    generate('scalar-spelling-pointer-alias', success=False, diagnostic='ENCBound:')
    header.write_text(types+'\nstatic void shadow(void) { struct Inner { void *p; }; }\n')
    generate('scoped-record-shadow')
    header.write_text(types+'\nstatic void shadow(void) { typedef void *Inner; }\n')
    generate('scoped-typedef-shadow')
    header.write_text(types)
    original = fragment.read_text()
    variants = {
        'const-output': ('bool *ok', 'const bool *ok'),
        'duplicate-attribute': ('[in,string]', '[in,in,string]'),
        'ignored-attribute-value': ('[in,string]', '[in=1,string]'),
        'private': ('public int run', 'int run'),
        'unknown-typedef': ('double number', 'Unknown number'),
        'reserved-parameter': ('double number', 'double _encbound_record_small'),
    }
    for name, (old, new) in variants.items():
        fragment.write_text(original.replace(old, new))
        generate(name, success=False)
    for name, (old, new) in {
        'pointer-return': ('public int run', 'public char *run'),
        'signed-count': ('size_t n', 'int64_t n'),
        'combined-extent': ('count=n', 'count=n,size=n'),
        'fixed-array': ('[in,out,count=n] uint32_t *words', '[in,out] uint32_t words[2][3]'),
        'inout-string': ('[in,string] char *text', '[in,out,string] char *text'),
        'wide-string': ('[in,string] char *text', '[in,out,wstring] wchar_t *text'),
    }.items():
        fragment.write_text(original.replace(old, new))
        generate(name)
    fragment.write_text(original)
    fragment.write_text(original.replace('[in,count=1] Packet *value', 'Packet value'))
    out = generate('implicit-memory-value')
    assert '__encbound_edl_app_run' in (out/'sample_app.c').read_text()
    assert 'const Packet* _encbound_record_value' in (out/'sample_app.h').read_text()
    fragment.write_text(original)
    header.write_text(types.replace('typedef struct Packet', 'typedef uint32_t Alias;\ntypedef struct Packet').replace('uint32_t sequence;', 'Alias sequence;'))
    fragment.write_text(original.replace('double number', 'Alias number'))
    generate('scalar-alias')
    header.write_text(types.replace('typedef struct Packet', 'typedef void *Alias;\ntypedef struct Packet'))
    generate('pointer-scalar-alias', success=False, diagnostic='unsupported value type')
    header.write_text(types)
    fragment.write_text(original)
    for key, value in (('sha256','0'*64), ('domain','application'), ('symbols',[])):
        changed = json.loads(json.dumps(policy))
        changed['sdk_only_imports']['sgx_tstdc.edl'][key] = value
        config.write_text(json.dumps(changed))
        generate('sdk-'+key, success=False, diagnostic='SDK import identity')
    config.write_text(json.dumps(policy))
    source.write_text(edl.replace('int emit([in,out,size=8]', 'int emit([user_check]'))
    generate('ocall-user-check')
    source.write_text(edl)
    source.write_text(edl.replace('import *;', 'import sgx_oc_cpuidex;').replace('int emit(', 'int sgx_thread_wait_untrusted_event_ocall('))
    generate('selective-import-shadow', success=False, diagnostic='application OCALL shadows SDK import')
    source.write_text(edl)
    # The actual parser's preprocessor, rather than a second text parser, decides
    # the active EDL. Header changes also force independent record revalidation.
    fragment.write_text('#if 0\nthis is deliberately invalid EDL\n#endif\n'+original)
    generate('preprocessed')

(BUILD/'results.json').write_text(json.dumps(rows, indent=2)+'\n')
print('NATIVE EDGER8R ADMISSION PASS:', len(rows), 'admission cases; 3 native execution rows, 6 terminal OCALL extent controls; nested layouts, dependency hashes and stock equivalence')
