#!/usr/bin/env python3
"""Build and verify matched SDK SIM rows for the required ECALL subsets."""
import argparse
import json
from pathlib import Path
import subprocess
from prepare import HERE, ROOT, PINS, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', choices=PINS, required=True)
    parser.add_argument('--out', type=Path, default=ROOT/'build/posup-trustfl/all-compat-v1-final')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    (out/args.app).mkdir(parents=True, exist_ok=True)
    rows = []
    for profile, base in [('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
                          ('MAC27', '0x40000000'), ('MAC27', '0x140000000')]:
        label = profile+('-high' if base != '0x40000000' else '')
        build = out/args.app/label
        if not args.skip_build:
            command = ['python3', str(HERE/'build.py'), '--app', args.app, '--profile', profile,
                       '--base', base, '--out', str(build)]
            with (out/args.app/(label+'.log')).open('w') as log:
                result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                raise SystemExit('build failed; see '+str(out/args.app/(label+'.log')))
        subprocess.run(['python3', HERE/'audit.py', '--build', build], cwd=ROOT, check=True)
        lines = (build/'logs/functional.log').read_text().splitlines()
        response = json.loads(next(line for line in lines if line.startswith('{')))
        assert response == dict(result='PASS', calls=54 if args.app == 'POSUP' else 5,
                               comparisons=234 if args.app == 'POSUP' else 5820000), response
        assert any('loaded app page permissions: PASS' in line for line in lines)
        probe = json.loads((build/'probe.json').read_text())
        assert next(row for row in probe['commands'] if row['name'] == 'functional')['returncode'] == 0
        rows.append(dict(app=args.app, profile=profile, base=base, build=str(build), mode='SDK SIM',
            functional=response, signed_sha256=sha(build/'enclave/enclave.signed.so'),
            record_hashes={name:sha(build/name) for name in ('probe.json', 'build.json', 'prepared.json', 'inventory.json', 'logs/functional.log')}))
        (out/args.app/'results.json').write_text(json.dumps(dict(pin=PINS[args.app], rows=rows,
            claims=dict(bounded_functionality=True, protection=False, hardware=False, performance=False,
                        complete_upstream_application=False)), indent=2)+'\n')
        print(args.app, label, 'SDK SIM PASS', response, flush=True)


if __name__ == '__main__':
    main()
