#!/usr/bin/env python3
"""Verify the vendored SDK RTTI and recover its exact upstream bytes offline."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent / 'sdk'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify():
    pins = json.loads((ROOT / 'pins.json').read_text())
    assert digest(ROOT / 'encbound.patch') == pins['patch_sha256'], 'RTTI patch pin'
    with tempfile.TemporaryDirectory(prefix='encbound-rtti-') as name:
        recovered = Path(name)
        for path, expected in pins['adapted'].items():
            data = (ROOT / path).read_bytes()
            assert hashlib.sha256(data).hexdigest() == expected, 'RTTI source pin: ' + path
            (recovered / path).write_bytes(data)
        subprocess.run(['patch', '--batch', '--silent', '-R', '-p1',
                        '-i', str(ROOT / 'encbound.patch')], cwd=recovered, check=True)
        for path, expected in pins['upstream'].items():
            assert digest(recovered / path) == expected, 'RTTI upstream recovery: ' + path
    print('SDK RTTI SOURCE / REVERSE PATCH PINS PASS')


if __name__ == '__main__':
    verify()
