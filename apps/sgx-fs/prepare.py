#!/usr/bin/env python3
"""Fetch pinned upstream inputs inside this repository; execute no installer."""
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = ROOT / 'build/sgx-fs'
DEPS = BASE / 'deps'
SDK = DEPS / 'sdk-package/package'
INTEL_ORIGIN = 'https://github.com/intel/linux-sgx.git'
INTEL_REVISION = '8e9ed532cc9b4dc4f86e6d2e1fef45e411892233'
INSTALLER_URL = 'https://download.01.org/intel-sgx/sgx-linux/2.26/distro/ubuntu24.04-server/sgx_linux_x64_sdk_2.26.100.0.bin'
INSTALLER_HASH = '6a067a46463f7bae11310d47fbcdf199e405dfbd100e10105dee415a7a496b0d'


def run(*args):
    subprocess.run(list(map(str, args)), check=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checkout(origin, revision, path, tag=None):
    if not path.exists():
        run('git', 'clone', '--no-checkout', *(['--depth', '1', '--branch', tag] if tag else []), origin, path)
        run('git', '-C', path, 'checkout', '--detach', revision)
    assert path.resolve().is_relative_to(ROOT)
    actual = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    assert actual == revision, (path, actual)
    assert not subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain'], text=True).strip(), path
    return dict(origin=origin, revision=actual, path=str(path))


def main():
    DEPS.mkdir(parents=True, exist_ok=True)
    pins = json.loads((HERE / 'pins.json').read_text())
    app = checkout(pins['repository'], pins['revision'], BASE / 'source')
    intel = checkout(INTEL_ORIGIN, INTEL_REVISION, DEPS / 'intel-sgx', 'sgx_2.26')
    for name, expected in pins['files'].items():
        assert digest(BASE / 'source' / name) == expected, name
    for name, expected in pins['math'].items():
        assert digest(DEPS / 'intel-sgx/sdk/tlibc' / name) == expected, name
    installer = DEPS / 'sdk-installer.bin'
    if not installer.exists():
        run('curl', '-fL', '--retry', '2', INSTALLER_URL, '-o', installer)
    assert digest(installer) == INSTALLER_HASH, 'SDK installer pin mismatch'
    if not SDK.exists():
        # This pinned self-extracting file has 216 shell lines before gzip.
        # Unpack its payload locally; its installation scripts are never run.
        payload = installer.read_bytes().split(b'\n', 216)[216]
        assert payload.startswith(b'\x1f\x8b\x08')
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            archive.extractall(DEPS / 'sdk-package', filter='data')
    run('python3', ROOT / 'tools/check_sdk_pins.py', '--sdk', SDK, '--pinned', DEPS / 'intel-sgx')
    record = dict(application=app, intel_source=intel, sdk=dict(url=INSTALLER_URL, installer_sha256=INSTALLER_HASH, path=str(SDK)))
    (BASE / 'dependencies.json').write_text(json.dumps(record, indent=2) + '\n')
    print('SGX-FS ORIGIN INPUTS VERIFIED', BASE)


if __name__ == '__main__':
    main()
