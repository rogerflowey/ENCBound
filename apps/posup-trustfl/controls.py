#!/usr/bin/env python3
"""Exercise rejection of corrupted source, object, manifest and bridge evidence.

Run only on idle saved builds. Each mutation restores the exact original bytes
in a finally block; the saved matrix verifier then checks those identities.
"""
import argparse
import json
from pathlib import Path
import subprocess
from prepare import HERE, ROOT, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT/'build/posup-trustfl/all-compat-v1-final')
    args = parser.parse_args()
    out = args.out.resolve()
    controls = out/'audit-controls'
    controls.mkdir(exist_ok=False)
    cases = []
    for app in ('POSUP', 'TrustFL'):
        build = out/app/'MAC27'
        compiled = build/'objects/Enclave.integration.json'
        unit = json.loads(compiled.read_text())
        unit['settings']['ENCBOUND_PROTECTED_GLOBALS'] = '0'
        bridge_path = build/'generated/boundary-manifest.json'
        bridge = json.loads(bridge_path.read_text())
        bridge['ecalls'] += ['undeclared_raw_entry']
        tests = [
            ('changed-body', build/'prepared/Enclave.cpp', (build/'prepared/Enclave.cpp').read_bytes()+b'\n/* damaged source */\n', 'prepared drift'),
            ('changed-object', build/'enclave/Enclave.o', (build/'enclave/Enclave.o').read_bytes()+b'damaged', 'input drift'),
            ('mixed-preset', compiled, (json.dumps(unit)+'\n').encode(), 'ENCBOUND_PROTECTED_GLOBALS'),
            ('changed-bridge', bridge_path, (json.dumps(bridge)+'\n').encode(), 'AssertionError'),
        ]
        for label, path, damaged, diagnostic in tests:
            saved = path.read_bytes()
            digest = sha(path)
            try:
                path.write_bytes(damaged)
                proc = subprocess.run(['python3', HERE/'audit.py', '--build', build], cwd=ROOT,
                                      text=True, capture_output=True, timeout=120)
            finally:
                path.write_bytes(saved)
            assert sha(path) == digest, 'control failed to restore exact artifact'
            text = proc.stdout+proc.stderr
            log = controls/(app+'-'+label+'.log')
            log.write_text(text)
            assert proc.returncode != 0 and diagnostic in text, (app, label, text[-2000:])
            cases.append(dict(app=app, case=label, returncode=proc.returncode, mutated=str(path),
                restored_sha256=digest, log=str(log), log_sha256=sha(log)))
            print(app, label, 'REJECTED; original bytes restored', flush=True)
    (controls/'results.json').write_text(json.dumps(cases, indent=2)+'\n')


if __name__ == '__main__':
    main()
