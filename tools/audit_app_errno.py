#!/usr/bin/env python3
"""Verify the serial application errno provider's definition and ownership.

Called by the ordinary closed ELF audit. The provider is application code;
SDK/runtime errno remains private and may coexist under its original names.
"""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LOCATION = '__encbound_app_errno_location'
STORE = '__encbound_app_errno_store'
SYMBOLS = {LOCATION, STORE}
RAW = {'errno', '__errno', '__errno_location', 'app_fmt___errno', 'app_fmt___errno_location'}


def names(path, flag, *, global_only=True):
    result = subprocess.run(['nm', *(['-g'] if global_only else []), flag, str(path)],
                            text=True, capture_output=True, check=True)
    return {line.split()[-1] for line in result.stdout.splitlines() if line.strip()}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError('application errno: '+message)


def audit(image, app, trusted):
    definitions = {obj: names(obj, '--defined-only') for obj in app+trusted}
    references = {obj: names(obj, '--undefined-only') for obj in app+trusted}
    if not any((definitions[obj] | references[obj]) & SYMBOLS for obj in app+trusted):
        return
    for obj in trusted:
        require(not definitions[obj] & SYMBOLS, 'provider defined in trusted object: '+str(obj))
        require(LOCATION not in references[obj], 'trusted code requests application errno pointer: '+str(obj))
    owners = {symbol: [obj for obj in app if symbol in definitions[obj]] for symbol in SYMBOLS}
    require(all(len(objects) == 1 for objects in owners.values()), 'missing or duplicate provider')
    provider = owners[LOCATION][0]
    require(owners[STORE] == [provider], 'split provider definitions')
    source = ROOT/'libc/errno.c'
    unit_path = provider.with_suffix('.integration.json')
    require(unit_path.is_file(), 'provider compilation manifest missing')
    unit = json.loads(unit_path.read_text())
    require(unit['settings'].get('ENCBOUND_APP_ERRNO') == '1', 'provider environment missing')
    require(unit['inputs'].get(str(source)) == digest(source), 'provider source identity')
    for path, expected in unit['inputs'].items():
        require(digest(path) == expected, 'provider input changed: '+path)
    placement = json.loads(Path(str(provider)+'.ownership.json').read_text())
    require(unit['object_sha256'] == placement['input_sha256'] and
            digest(provider) == placement['output_sha256'], 'provider compile/placement identity')
    for suffix, key in (('.input.ll', 'input_ir_sha256'), ('.checked.ll', 'checked_ir_sha256')):
        require(digest(provider.with_suffix(suffix)) == unit[key], 'provider retained IR identity')
    from encbound_inventory import get_marker
    profile = unit['settings']['ENCBOUND_PROFILE']
    expected_marker = None if profile == 'BASELINE' else profile
    require(get_marker(provider) == expected_marker, 'provider profile/domain mismatch')
    for obj in app:
        require(get_marker(obj) == expected_marker, 'mixed application/provider profiles')
        require(not (definitions[obj] | references[obj]) & RAW,
                'raw or separate errno symbol: '+str(obj))
        if references[obj] & SYMBOLS:
            record_path = obj.with_suffix('.integration.json')
            require(record_path.is_file(), 'errno caller manifest missing: '+str(obj))
            record = json.loads(record_path.read_text())
            require(record['settings'].get('ENCBOUND_APP_ERRNO') == '1',
                    'errno caller environment missing: '+str(obj))
    required = set().union(*(references[obj] & SYMBOLS for obj in app+trusted))
    # A final executable may localize hidden application functions.
    require(required <= names(image, '--defined-only', global_only=False), 'provider missing from final image')
    print('APPLICATION ERRNO PROVIDER / OWNERSHIP PASS')
