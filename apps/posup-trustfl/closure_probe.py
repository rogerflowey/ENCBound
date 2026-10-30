#!/usr/bin/env python3
"""Follow original-unit diagnostics past known definition/adapter setup gaps.

These are native compiler probes only. Nothing here enters the selected SDK SIM
images. Adapter mappings name existing checked implementations, never raw SDK
services. Their complete full-application link/lifetime port is not claimed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import subprocess
from prepare import HERE, ROOT, sha
from build import SDK_SRC


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT/'build/posup-trustfl/all-compat-v1-final')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    rows = []
    for app in ('POSUP', 'TrustFL'):
        for profile in ('RADIX_ONLY', 'MAC27'):
            build = args.out.resolve()/app/profile
            out = build/'closure-followup'
            if out.exists():
                parser.error('followup output exists; preserve it and use a fresh matrix')
            out.mkdir()
            q = json.loads((build/'probe.json').read_text())
            command = next(row['command'] for row in q['commands'] if row['name'] == 'original-frontend')
            flags, original = command[1:command.index('-S')], Path(command[-3])
            row = dict(app=app, profile=profile, mode='native compiler only', commands=[],
                       original_source=str(original), original_sha256=sha(original))
            env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_CXX_EH='0',
                ENCBOUND_KEEP_GEP_FLAGS='0', ENCBOUND_POST_INSTCOMBINE='0',
                ENCBOUND_PLUGIN=str(build/'toolchain/pass/encbound_pass.so'),
                ENCBOUND_LIBCXX_PREPARED=str(build/'libcxx-prepared'))
            wrap = [ROOT/'tools/with-integration-defaults.sh']

            def run(name, cmd):
                cmd = list(map(str, cmd))
                proc = subprocess.run(cmd, env=env, cwd=ROOT, text=True, capture_output=True, timeout=600)
                log = out/(name+'.log')
                log.write_text(proc.stdout+proc.stderr)
                result = dict(name=name, command=cmd, returncode=proc.returncode, log=str(log), sha256=sha(log),
                    diagnostics=[line for line in (proc.stdout+proc.stderr).splitlines() if 'LLVM ERROR:' in line or 'error:' in line])
                row['commands'].append(result)
                (out/'results.json').write_text(json.dumps(row, indent=2)+'\n')
                print(app, profile, name, proc.returncode, *result['diagnostics'][:1], flush=True)
                return proc

            text = (build/'original-admitted.txt').read_text()
            text += (build/'original-generated/admitted-ocalls.txt').read_text()
            if app == 'POSUP':
                block = original.parent/'BlockSGX.cpp'
                ir = out/'BlockSGX.frontend.ll'
                assert run('block-frontend', ['clang-21', *flags, '-S', '-emit-llvm', block, '-o', ir]).returncode == 0
                definitions = set(re.findall(r'^define .*?@([^ (]+)\(', ir.read_text(), re.M))
                definitions.update(re.findall(r'^@([^ ]+) = .*?alias ', ir.read_text(), re.M))
                text += '\n'.join(sorted(definitions))+'\n'
                text += 'sgx_aes_ctr_encrypt = encbound_proto_aes_encrypt\nsgx_aes_ctr_decrypt = encbound_proto_aes_decrypt\n'
                row['existing_adapters'] = {str(ROOT/'apps/sgx-enclave-protocol/adapters.c'): sha(ROOT/'apps/sgx-enclave-protocol/adapters.c')}
                row['extra_sources'] = {str(block):sha(block)}
            else:
                # Rebuild the supported library with this actual original caller;
                # an absent library definition is not invented in the inventory.
                assert run('original-libcxx', [*wrap, 'python3', ROOT/'apps/libcxx/build.py',
                    '--profile', profile, '--out-dir', out/'libcxx', '--caller', original,
                    *['--caller-flag='+f for f in flags]]).returncode == 0
                text += (out/'libcxx/admitted.txt').read_text()
                text += ('sgx_sha256_init = encbound_tpdv_sha_init\n'
                         'sgx_sha256_update = encbound_tpdv_sha_update\n'
                         'sgx_sha256_get_hash = encbound_tpdv_sha_get\n')
                row['existing_adapters'] = {str(ROOT/'apps/tpdv/adapters.c'):sha(ROOT/'apps/tpdv/adapters.c')}
                row['adapter_limit'] = 'Diagnostic mapping only. Full port must reconcile SHA update length ABI and close leaked contexts; no raw SDK handle is exposed.'
            admitted = out/'admitted.txt'
            admitted.write_text(text)
            env['ENCBOUND_ADMITTED'] = str(admitted)
            row['full_unit_rc'] = run('full-unit', [*wrap, ROOT/'tools/encbound-cc.sh', original,
                out/'original.o', *flags]).returncode
            if app == 'POSUP':
                row['block_rc'] = run('block-application', [*wrap, ROOT/'tools/encbound-cc.sh', block,
                    out/'BlockSGX.o', *flags]).returncode
            row['inputs'] = {str(x):sha(x) for x in (Path(__file__), build/'probe.json', admitted,
                Path(env['ENCBOUND_PLUGIN']), ROOT/'config/integration.env')}
            (out/'results.json').write_text(json.dumps(row, indent=2)+'\n')
            rows.append(row)
    (args.out/'closure-followup.json').write_text(json.dumps(rows, indent=2)+'\n')


if __name__ == '__main__':
    main()
