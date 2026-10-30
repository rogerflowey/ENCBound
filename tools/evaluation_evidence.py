#!/usr/bin/env python3
"""Unique retained run directories and input identities for SDK SIM evaluation.

The SDK diagnostic runners and wallet matrix need independent records
per configuration/run, including the actual signed image used. No execution or
result classification happens here.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def new_run(build, kind, output_root=None):
    parent = (output_root or ROOT / 'build/evaluation-runs').resolve() / kind / build.name
    parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S-')
    return Path(tempfile.mkdtemp(prefix=stamp, dir=parent))


def capture(run_dir, build, runner, enclave_dir=None, host=None):
    enclave = enclave_dir or build / 'enclave'
    artifacts = run_dir / 'artifacts'
    artifacts.mkdir()  # Fail on reuse; never replace a previous run's inputs.
    files = {'host': host or build / 'host/host', 'enclave.so': build / 'enclave/enclave.so',
             'enclave.signed.so': enclave / 'enclave.signed.so', 'runner': runner,
             'pass-plugin.so': ROOT / 'build/pass/encbound_pass.so'}
    for name in ['build-config.json', 'semantic-fixture-coverage.json',
                 'build-identity.json', 'inventory.json']:
        if (build / name).exists():
            files[name] = build / name
    for name in ['enclave.config.final.xml', 'enclave.config.high.xml']:
        if (build / name).exists():
            files[name] = build / name
    identities = {}
    for name, path in files.items():
        shutil.copy2(path, artifacts / name)
        identities[name] = {'path': str(path.resolve()), 'sha256': digest(artifacts / name)}
    # Each record can be bound to the source/driver/oracle revision even after
    # the build is replaced. The correction campaign separately archives sources.
    sources = {}
    for directory in ['pass', 'runtime', 'include', 'sdk', 'wrappers', 'tools', 'tests/pass', 'apps']:
        for path in sorted((ROOT / directory).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts:
                sources[str(path.relative_to(ROOT))] = digest(path)
    objects = {p.name: digest(p) for p in sorted((build / 'enclave').glob('*.o'))}
    record = {'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'build': str(build.resolve()), 'enclave_dir': str(enclave.resolve()),
              'artifacts': identities, 'objects': objects, 'sources': sources}
    (run_dir / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    (run_dir / 'identities.txt').write_text(''.join(
        f'{name} sha256 {item["sha256"]}\n' for name, item in identities.items()))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='command', required=True)
    new = sub.add_parser('new')
    new.add_argument('--build', type=Path, required=True)
    new.add_argument('--kind', required=True, choices=['forgery', 'lz4', 'lz4-nocompat',
                     'runtime', 'runtime-high', 'wallet-upstream', 'wallet-overflow'])
    new.add_argument('--root', type=Path)
    cap = sub.add_parser('capture')
    cap.add_argument('--run-dir', type=Path, required=True)
    cap.add_argument('--build', type=Path, required=True)
    cap.add_argument('--runner', type=Path, required=True)
    cap.add_argument('--enclave-dir', type=Path)
    cap.add_argument('--host', type=Path)
    config = sub.add_parser('config')
    config.add_argument('--build', type=Path, required=True)
    config.add_argument('--fast-paths',choices=['off','inline','loops'],default='off')
    config.add_argument('--check-reuse',choices=['off','block','loop'],default='off')
    config.add_argument('--local-proofs',type=int,choices=[0,1],default=0)
    config.add_argument('--codegen', choices=['-O0', '-O2'], default='-O0')
    for name in ['profile', 'frontend', 'base', 'debug', 'mode', 'sdk', 'pinned', 'appdata']:
        config.add_argument('--' + name, required=True)
    args = ap.parse_args()
    if args.command == 'new':
        print(new_run(args.build.resolve(), args.kind, args.root))
    elif args.command == 'capture':
        capture(args.run_dir, args.build, args.runner, args.enclave_dir, args.host)
    else:
        data = {k: v for k, v in vars(args).items() if k not in ['command', 'build']}
        (args.build / 'build-config.json').write_text(json.dumps(data, indent=2) + '\n')


if __name__ == '__main__':
    main()
