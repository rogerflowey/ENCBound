#!/usr/bin/env python3
"""Probe the real sk-sgx application closure; never admit undefined services.

Uses the all-compat preset, native modified EDL generator and exact trusted
adapter mappings. Cross-unit admission is generated ONLY from externally
visible definitions in the ten pinned application source units.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
SDK_SRC = Path(os.environ.get('PINNED_SRC', str(ROOT/'deps/intel-sgx')))
UNITS = 'enclave ed25519 fe25519 ge25519 sc25519 sha256blocks sha256hash sha512blocks sha512hash verify'.split()
MAPPINGS = {
    'sgx_read_rand': 'encbound_sk_rand',
    'sgx_calc_sealed_data_size': 'encbound_sk_calc_sealed_data_size',
    'sgx_get_encrypt_txt_len': 'encbound_sk_get_encrypt_txt_len',
    'sgx_get_add_mac_txt_len': 'encbound_sk_get_add_mac_txt_len',
    'sgx_seal_data': 'encbound_sk_seal_data',
    'sgx_unseal_data': 'encbound_sk_unseal_data',
    'consttime_memequal': 'encbound_sk_consttime_memequal',
    'memset_s': 'encbound_sk_memset_s',
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--profile', choices=('BASELINE', 'RADIX_ONLY', 'MAC27'), required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--scalar', action='store_true', help='matched frontend without vectorization; all memory checks retained')
    args = ap.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for name in ('ir', 'generated', 'objects'):
        (out / name).mkdir()
    upstream = HERE / 'upstream'
    pins = json.loads((HERE / 'pins.json').read_text())
    assert all(sha(upstream / n) == h for n, h in pins['files'].items()), 'source pin drift'
    source = out / 'prepared'
    shutil.copytree(upstream, source)
    original = 'malloc(aadlen)'
    adapted = 'malloc(aadlen ? aadlen : 1)'
    enclave_source = source / 'enclave.c'
    assert enclave_source.read_text().count(original) == 1
    enclave_source.write_text(enclave_source.read_text().replace(original, adapted))
    record = dict(profile=args.profile, preset='all-compat-v1', scope='complete non-debug upstream enclave closure',
                  source=pins, commands=[], inputs={str(upstream/n): h for n, h in pins['files'].items()},
                  adaptations=[dict(file='enclave.c', before=original, after=adapted,
                                    reason='Preserve the pinned zero-length AAD path when ENCBound allocators reject malloc(0)')],
                  prepared={n: sha(source/n) for n in pins['files']})
    record['inputs'].update({str(p): sha(p) for p in
        (HERE/'probe.py', HERE/'adapters.c', HERE/'adapters.h', HERE/'boundary-interface.json',
         ROOT/'config/integration.env', ROOT/'tools/with-integration-defaults.sh',
         ROOT/'tools/modified_bridge.py', ROOT/'tools/encbound-cc.sh',
         ROOT/'build/pass/encbound_pass.so', ROOT/'build/edger8r/sgx_edger8r')})

    def save():
        (out / 'probe.json').write_text(json.dumps(record, indent=2) + '\n')

    def run(name, command, fail=True, env=None):
        command = list(map(str, command))
        result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=180)
        log = out / (name + '.log')
        log.write_text(result.stdout + result.stderr)
        record['commands'].append(dict(name=name, command=command, returncode=result.returncode,
                                        log=str(log), sha256=sha(log)))
        save()
        print(name, 'PASS' if result.returncode == 0 else 'FAIL', flush=True)
        if result.returncode and fail:
            raise SystemExit(result.stderr[-3000:] + '\nSee ' + str(log))
        return result

    run('sdk-pins', [sys.executable, ROOT/'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', SDK_SRC])
    edl = out/'sk.edl'
    text = (source/'sk.edl').read_text()
    assert text.count('enclave {') == 1
    edl.write_text(text.replace('enclave {', 'enclave {\n    from "sgx_tstdc.edl" import *;'))
    config = json.loads((HERE/'boundary-interface.json').read_text())
    interface = out/'boundary-interface.json'
    interface.write_text(json.dumps(config, indent=2)+'\n')
    includes = ['-I'+str(p) for p in (source, out/'generated', ROOT/'sdk', ROOT/'include', ROOT/'runtime',
                                     SDK/'include', SDK/'include/tlibc', SDK_SRC/'common/inc/internal')]
    flags = ['-O2', '-g', '-fno-builtin', '-fno-common', '-nostdinc', '-fpie', '-fvisibility=hidden',
             '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong', *includes]
    if args.scalar:
        flags += ['-fno-vectorize', '-fno-slp-vectorize']
    record['frontend_flags'] = flags
    run('bridge', [sys.executable, ROOT/'tools/modified_bridge.py', '--edl', edl, '--interface', interface,
                  '--generator', ROOT/'build/edger8r/sgx_edger8r', '--out-dir', out/'generated',
                  '--profile', args.profile, '--search-path', out, '--search-path', SDK/'include',
                  *['--cflag='+f for f in includes + ['-nostdinc']]])
    definitions = {}
    # Inventory is based only on actual external definitions, with their owning
    # source file and IR recorded. No undefined symbol is admitted automatically.
    for unit in UNITS:
        ir = out/'ir'/f'{unit}.ll'
        run(unit+'-inventory', ['clang-21', '-S', '-emit-llvm', *flags, source/f'{unit}.c', '-o', ir])
        for line in ir.read_text().splitlines():
            if line.startswith('define ') and not re.search(r'\b(?:internal|private)\b', line):
                name = re.search(r'@([^ (]+)\(', line).group(1)
                assert name not in definitions, 'duplicate application definition: '+name
                definitions[name] = dict(source=str(source/f'{unit}.c'), ir=str(ir), ir_sha256=sha(ir))
    assert not definitions.keys() & MAPPINGS.keys()
    record['definitions'] = definitions
    admitted = out/'admitted.txt'
    admitted.write_text('\n'.join(sorted(definitions))+'\n'+
                        '\n'.join(k+' = '+v for k,v in MAPPINGS.items())+'\n'+
                        (out/'generated/admitted-app.txt').read_text()+
                        (out/'generated/admitted-ocalls.txt').read_text())
    record['adapter_mappings'] = MAPPINGS
    # Compile the adapter implementation as trusted code before using mappings.
    for name, src in [('sk-adapters', HERE/'adapters.c'), ('sealing-adapters', ROOT/'wrappers/sdk_adapters.c')]:
        run(name, ['clang-21', *flags, '-I'+str(ROOT/'wrappers'), '-c', src, '-o', out/'objects'/f'{name}.o'])
    env = dict(os.environ, ENCBOUND_PROFILE=args.profile, ENCBOUND_ADMITTED=str(admitted))
    rows = []
    for unit in UNITS:
        obj = out/'objects'/f'{unit}.o'
        result = run(unit+'-application', [ROOT/'tools/with-integration-defaults.sh', ROOT/'tools/encbound-cc.sh',
                     source/f'{unit}.c', obj, *flags], fail=False, env=env)
        rows.append(dict(unit=unit, returncode=result.returncode))
    record['application_rows'] = rows
    record['admission_passed'] = all(r['returncode'] == 0 for r in rows)
    save()
    print('Complete closure admission:', record['admission_passed'], out, flush=True)


if __name__ == '__main__':
    main()
