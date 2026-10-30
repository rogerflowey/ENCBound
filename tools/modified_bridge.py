#!/usr/bin/env python3
"""Run native edger8r admission/code generation and compile its ABI assertions.

No generated-C rewriting and no supplementary application input policy.
Intel's untrusted ABI is unchanged. SDK-only imports keep ordinary proxies.
Python handles build orchestration and evidence only; it never parses EDL.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import shlex


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def generate(args):
    source = Path(args.edl).resolve()
    config_path = Path(args.interface).resolve()
    sdk_ecall_contracts = Path(__file__).parent/'edger8r/sdk-ecalls.json'
    dependencies = {source, config_path, Path(__file__).resolve(),
                    Path(args.generator).resolve(), sdk_ecall_contracts.resolve()}
    # Fail before publication. The temporary paths never enter generated C.
    out = Path(args.out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='modified-bridge-', dir=out.parent) as tmp:
        tmp = Path(tmp)
        command = [str(Path(args.generator).resolve())]
        for path in args.search_path:
            command += ['--search-path', path]
        command += ['--trusted', '--trusted-dir', str(tmp), '--untrusted',
                    '--untrusted-dir', str(tmp), str(source)]
        flags_file = tmp/'compiler-flags.json'
        flags_file.write_text(json.dumps(args.cflag))
        env = {k: v for k, v in os.environ.items() if not k.startswith('ENCBOUND_BRIDGE_')}
        env.update(ENCBOUND_BRIDGE_CONFIG=str(config_path),
                   ENCBOUND_BRIDGE_SDK_ECALLS=str(sdk_ecall_contracts.resolve()),
                   ENCBOUND_BRIDGE_PROFILE=args.profile,
                   ENCBOUND_BRIDGE_CXX_EH=str(int(args.cxx_eh)),
                   ENCBOUND_BRIDGE_WIDE_SCALARS=str(int(args.wide_scalars)),
                   ENCBOUND_BRIDGE_LAYOUT_CC=args.layout_cc,
                   ENCBOUND_BRIDGE_FLAGS=str(flags_file), ENCBOUND_BRIDGE_WORK=str(tmp))
        subprocess.run(command, env=env, check=True)
        native = json.loads((tmp/'edger8r-admission.json').read_text())
        dependencies.update(Path(p).resolve() for p in native['dependencies'])
        # The generator supplies assertions and prototypes from its own AST.
        # Compiler diagnostics reject mismatched C layouts/signatures.
        for check in (tmp/'bridge-abi.c', tmp/(source.stem+'_t.c'), tmp/(source.stem+'_app.c')):
            dep = tmp/(check.name+'.d')
            cmd = [args.cc, '-fsyntax-only', '-MMD', '-MF', str(dep), '-I'+str(tmp)]
            cmd += args.cflag
            if args.profile != 'BASELINE':
                cmd += ['-DENCBOUND_PROTECTED']
            cmd += [str(check)]
            subprocess.run(cmd, check=True)
        for dep in tmp.glob('*.d'):
            prerequisites = dep.read_text().replace('\\\n', ' ').partition(':')[2]
            for name in shlex.split(prerequisites):
                path = Path(name).resolve()
                if path.is_file() and not path.is_relative_to(tmp):
                    dependencies.add(path)
        outputs = {source.stem+s: (tmp/(source.stem+s)).read_bytes()
                   for s in ('_t.c', '_t.h', '_u.c', '_u.h', '_app.c', '_app.h')}
        for name in ('admitted-ocalls.txt', 'admitted-app.txt', 'edger8r-admission.json', 'bridge-abi.c', 'eh-entries.txt'):
            outputs[name] = (tmp/name).read_bytes()
    generator_sources = Path(__file__).parent/'edger8r'
    dependencies.update(p.resolve() for p in generator_sources.iterdir() if p.is_file())
    dependencies.update((Path(__file__).parent.parent/'sdk'/p).resolve()
                        for p in ('modified_bridge.h', 'boundary_support.h'))
    if native['propagate_errno_ocalls']:
        dependencies.add((Path(__file__).parent.parent/'include'/'encbound_app_errno.h').resolve())
    manifest = {
        'wide_scalars': args.wide_scalars,
        'cxx_eh': args.cxx_eh, 'eh_entries': native['eh_entries'],
        'architecture': 'modified-intel-bridge', 'profile': args.profile,
        'admission': 'native Intel AST / ENCBound v1',
        'ecalls': native['ecalls'], 'user_check_ecalls': native['user_check_ecalls'],
        'application_ecalls': native['application_ecalls'],
        'sdk_ecalls': native['sdk_ecalls'], 'sdk_ecall_imports': native['sdk_ecall_imports'],
        'user_check_ocalls': native['user_check_ocalls'],
        'ocalls': native['ocalls'], 'sdk_only': native['sdk_only'],
        'imports': native['imports'],
        'application_definitions': native['application_definitions'],
        'trusted_ocalls': native['trusted_ocalls'],
        'propagate_errno_ocalls': native['propagate_errno_ocalls'],
        'required_application_symbols': native['required_application_symbols'],
        'runtime_policy': 'SDK EDL semantics; no application input/output filters',
        'toolchain': {'cc': args.cc, 'layout_cc': args.layout_cc, 'cflags': args.cflag},
        'inputs': {str(p): digest(p) for p in sorted(dependencies)},
        'outputs': {k: hashlib.sha256(v).hexdigest() for k,v in outputs.items()}}
    outputs['boundary-manifest.json'] = (json.dumps(manifest, indent=2)+'\n').encode()
    def escape(p):
        return str(p).replace('\\', '\\\\').replace(' ', '\\ ').replace('#', '\\#').replace('$', '$$')
    targets = ' '.join(escape(out/n) for n in outputs)
    # As with compiler -MP depfiles, permit regeneration after an obsolete
    # dependency is removed. Real missing inputs still fail in the generator.
    deptext = targets+': '+' '.join(escape(p) for p in sorted(dependencies))+'\n'
    deptext += ''.join(escape(p)+':\n' for p in sorted(dependencies))
    outputs['boundary.d'] = deptext.encode()
    for name, value in outputs.items():
        (out/name).write_bytes(value)
    print('modified-bridge: generated', args.profile, len(native['ecalls']), 'ECALLs,', len(native['ocalls']), 'OCALLs')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('edl', 'interface', 'generator', 'out-dir'):
        ap.add_argument('--'+name, required=True)
    ap.add_argument('--wide-scalars', action='store_true', help='compatibility option; ordinary scalar support is always enabled')
    ap.add_argument('--cxx-eh', action='store_true', help='require compiler-generated terminating ECALL entries in all profiles')
    ap.add_argument('--profile', choices=['BASELINE','RADIX_ONLY','MAC27'], required=True)
    ap.add_argument('--search-path', action='append', default=[])
    ap.add_argument('--cflag', action='append', default=[])
    ap.add_argument('--cc', default='cc')
    ap.add_argument('--layout-cc', default='clang-21')
    args = ap.parse_args()
    try:
        generate(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit('modified-bridge: FAIL: '+str(exc))
