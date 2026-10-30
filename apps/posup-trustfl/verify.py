#!/usr/bin/env python3
"""Verify saved row identities, command logs and complete closure audits."""
import argparse
import json
from pathlib import Path
import subprocess
from prepare import HERE, ROOT, PINS, sha


def verify(out):
    count = 0
    for app in PINS:
        results = json.loads((out/app/'results.json').read_text())
        assert results['pin'] == PINS[app]
        assert [(r['profile'], r['base']) for r in results['rows']] == [
            ('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
            ('MAC27', '0x40000000'), ('MAC27', '0x140000000')]
        for row in results['rows']:
            build = Path(row['build'])
            for name, digest in row['record_hashes'].items():
                assert sha(build/name) == digest, 'record drift '+name
                count += 1
            assert sha(build/'enclave/enclave.signed.so') == row['signed_sha256']
            probe = json.loads((build/'probe.json').read_text())
            for name, digest in probe.get('original_port', {}).get('files', {}).items():
                assert sha(name) == digest, 'original port drift '+name
                count += 1
            functional = next(c for c in probe['commands'] if c['name'] == 'functional')
            assert functional['returncode'] == 0
            response = json.loads(next(line for line in Path(functional['log']).read_text().splitlines() if line.startswith('{')))
            assert response == row['functional'] == dict(result='PASS', calls=54 if app == 'POSUP' else 5,
                comparisons=234 if app == 'POSUP' else 5820000)
            for command in probe['commands']:
                assert sha(command['log']) == command['sha256'], 'command log drift'
                count += 1
            subprocess.run(['python3', HERE/'audit.py', '--build', build], check=True, cwd=ROOT)
            assert sha(build/'inventory.json') == row['record_hashes']['inventory.json']
    for row in json.loads((out/'closure-followup.json').read_text()):
        assert row['mode'] == 'native compiler only' and row['full_unit_rc'] != 0
        for name, digest in {**row['inputs'], **row['existing_adapters'], **row.get('extra_sources', {})}.items():
            assert sha(name) == digest, 'diagnostic input drift '+name
            count += 1
        for command in row['commands']:
            assert sha(command['log']) == command['sha256'], 'diagnostic log drift'
            count += 1
    for row in json.loads((out/'audit-controls/results.json').read_text()):
        assert row['returncode'] != 0
        assert sha(row['log']) == row['log_sha256'] and sha(row['mutated']) == row['restored_sha256']
        count += 2
    print('SAVED MATRIX VERIFIED', count, 'record/log hashes; 8 complete closure audits')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT/'build/posup-trustfl/all-compat-v1-final')
    verify(parser.parse_args().out.resolve())
