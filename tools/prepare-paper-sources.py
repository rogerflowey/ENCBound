#!/usr/bin/env python3
"""Fetch exact pinned application inputs into build/, or verify a local cache."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe source path: '+name)
    return Path(*path.parts)


def prepare_git(name, spec, cache=None):
    """Retain the exact commit object required by the existing Git-based recipes."""
    destination = ROOT/'build/paper-sources'/safe_path(spec['destination'])
    def verify(checkout):
        top = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', '--show-toplevel'], text=True).strip()
        if Path(top).resolve() != checkout.resolve():
            raise ValueError('source must be its own Git checkout: '+str(checkout))
        revision = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
        if revision != spec['revision']:
            raise ValueError('source revision mismatch: '+name)
        for path, expected in spec['files'].items():
            relative = safe_path(path)
            committed = subprocess.check_output(['git', '-C', str(checkout), 'show', revision+':'+path])
            if digest(committed) != expected or digest((checkout/relative).read_bytes()) != expected:
                raise ValueError('source pin mismatch: '+name+'/'+path)
    if destination.exists():
        verify(destination)
        print(name, 'verified Git revision and', len(spec['files']), 'file pins')
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        stage = Path(temporary)/'source'
        subprocess.run(['git', 'init', '-q', str(stage)], check=True)
        origin = str(cache) if cache else spec['url']
        subprocess.run(['git', '-C', str(stage), 'fetch', '-q', '--depth=1', origin, spec['revision']], check=True)
        subprocess.run(['git', '-C', str(stage), '-c', 'advice.detachedHead=false', 'checkout', '-q', '--detach', spec['revision']], check=True)
        verify(stage)
        shutil.move(stage, destination)
    print(name, 'prepared Git revision and', len(spec['files']), 'file pins')


def prepare(name, spec, cache=None):
    if spec.get('format') == 'git':
        return prepare_git(name, spec, cache)
    destination = ROOT/'build/paper-sources'/safe_path(spec['destination'])
    expected = spec['files']
    if destination.is_dir() and all((destination/path).is_file() for path in expected):
        for path, sha in expected.items():
            if digest((destination/path).read_bytes()) != sha:
                raise ValueError('existing source changed: '+str(destination/path))
        print(name, 'verified', len(expected), 'files')
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        stage = Path(temporary)/'source'
        stage.mkdir()
        contents = {}
        if cache:
            for path in expected:
                contents[path] = (cache/safe_path(path)).read_bytes()
        else:
            request = Request(spec['url'], headers={'User-Agent': 'ENCBound-paper-artifact'})
            with urlopen(request, timeout=180) as response:
                data = response.read()
            if spec.get('archive_sha256') and digest(data) != spec['archive_sha256']:
                raise ValueError('archive pin mismatch: '+name)
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                for member in archive:
                    parts = PurePosixPath(member.name).parts
                    relative = '/'.join(parts[1:])
                    if relative not in expected:
                        continue
                    if not member.isfile() or relative in contents:
                        raise ValueError('unexpected archive member: '+member.name)
                    contents[relative] = archive.extractfile(member).read()
        for path, sha in expected.items():
            if path not in contents or digest(contents[path]) != sha:
                raise ValueError('source pin mismatch: '+name+'/'+path)
            target = stage/safe_path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents[path])
        if destination.exists():
            raise ValueError('incomplete destination; choose a fresh build tree: '+str(destination))
        shutil.move(stage, destination)
    print(name, 'prepared', len(expected), 'files')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    specs = json.loads((ROOT/'config/paper-sources.json').read_text())
    parser.add_argument('--app', choices=[*specs, 'all'], default='all')
    parser.add_argument('--from-cache', action='append', default=[], metavar='NAME=DIR',
                        help='verify exact files from an existing source checkout instead of downloading')
    args = parser.parse_args()
    caches = {}
    for value in args.from_cache:
        name, directory = value.split('=', 1)
        if name not in specs:
            parser.error('unknown source cache: '+name)
        caches[name] = Path(directory).resolve()
    names = list(specs) if args.app == 'all' else ([args.app, 'fflib'] if args.app=='yeez' else [args.app])
    for name in names:
        prepare(name, specs[name], caches.get(name))


if __name__ == '__main__':
    main()
