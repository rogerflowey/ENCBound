#!/usr/bin/env python3
"""Fetch only pinned USIG inputs and retain upstream licenses unchanged."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PINS = json.loads((HERE / 'pins.json').read_text())
SOURCE = ROOT / 'build/paper-sources/go-consensus-usig'


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def prepare():
    if not all((SOURCE / n).is_file() and sha(SOURCE / n) == h for n, h in PINS['files'].items()):
        archive = SOURCE.parent / 'upstream.tar.gz'
        archive.parent.mkdir(parents=True, exist_ok=True)
        if not archive.exists() or sha(archive) != PINS['archive_sha256']:
            urllib.request.urlretrieve('https://codeload.github.com/' + PINS['repository'] + '/tar.gz/' + PINS['revision'], archive)
        assert sha(archive) == PINS['archive_sha256'], 'archive pin drift'
        with tarfile.open(archive) as tar:
            for n, h in PINS['files'].items():
                data = tar.extractfile('go-consensus-' + PINS['revision'] + '/' + n).read()
                assert hashlib.sha256(data).hexdigest() == h
                dest = SOURCE / n
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
    assert all(sha(SOURCE / n) == h for n, h in PINS['files'].items())
    return SOURCE / 'enclaves/usig/enclave_usig'


if __name__ == '__main__':
    print(prepare())
