#!/usr/bin/env python3
"""Audit application-only explicit variadic callbacks in a closed link.

This binds compiler ABI records to retained builds and actual definitions. It
does not validate runtime callback targets or provide control-flow integrity.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from encbound_inventory import get_marker

PREFIX = '__encbound_va_'


def require(condition, message):
    if not condition:
        raise ValueError('application variadics: '+message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def symbols(path, flag):
    result = subprocess.run(['nm', flag, str(path)], text=True, capture_output=True, check=True)
    return {line.split()[-1] for line in result.stdout.splitlines() if line.strip()}


def records(path):
    # ELF permits multiple sections with the same name (e.g. separate constant
    # strings and eight-byte feature markers). Do not collapse them into a dict.
    data = Path(path).read_bytes()
    require(data[:6] == b'\x7fELF\x02\x01', 'expected little-endian ELF64')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entry_size, count, names_index = struct.unpack_from('<HHH', data, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*entry_size) for i in range(count)]
    names_header = headers[names_index]
    names = data[names_header[4]:names_header[4]+names_header[5]]
    raw = b'\0'.join(data[h[4]:h[4]+h[5]] for h in headers
                     if names[h[0]:].split(b'\0', 1)[0] == b'.encbound.abi')
    # Other compiler ABI metadata shares the section. NUL separates payloads.
    return [line for part in raw.split(b'\0') for line in part.decode('utf-8', 'replace').splitlines()
            if 'encbound-va-' in line]


def audit(image, app, trusted):
    all_records = {obj: records(obj) for obj in app+trusted}
    # Historical direct-only builds retain their original acceptance route.
    if not any(line.startswith(('A ', 'I ')) for lines in all_records.values() for line in lines):
        return
    definitions = {obj: symbols(obj, '--defined-only') for obj in app+trusted}
    references = {obj: symbols(obj, '--undefined-only') for obj in app+trusted}
    for obj in trusted:
        require(not all_records[obj] and not any(n.startswith(PREFIX) for n in definitions[obj]|references[obj]),
                'private callback ABI in trusted object: '+str(obj))
    owners = {}
    signatures = {}
    profiles = set()
    for obj in app:
        unit_path = obj.with_suffix('.integration.json')
        require(unit_path.is_file(), 'compilation manifest missing: '+str(obj))
        unit = json.loads(unit_path.read_text())
        settings = unit['settings']
        profile = settings.get('ENCBOUND_PROFILE')
        profiles.add(profile)
        require(profile in ('BASELINE', 'RADIX_ONLY', 'MAC27') and settings.get('ENCBOUND_VARIADICS') == '1',
                'inconsistent application ABI configuration: '+str(obj))
        require(get_marker(obj) == (None if profile == 'BASELINE' else profile), 'profile/domain mismatch: '+str(obj))
        placement = json.loads(Path(str(obj)+'.ownership.json').read_text())
        require(unit['object_sha256'] == placement['input_sha256'] and digest(obj) == placement['output_sha256'],
                'compile/placement identity: '+str(obj))
        for suffix, key in (('.input.ll', 'input_ir_sha256'), ('.checked.ll', 'checked_ir_sha256')):
            require(digest(obj.with_suffix(suffix)) == unit[key], 'retained IR identity: '+str(obj))
        for source, expected in unit['inputs'].items():
            require(digest(source) == expected, 'build input changed: '+source)
        checked = obj.with_suffix('.checked.ll').read_text()
        for line in checked.splitlines():
            if re.match(r'^(define|declare) .*\.\.\.', line):
                require(line.startswith('declare ') and re.search(r'@(encbound_eh_personality|__gxx_personality_v0)\(', line),
                        'native variadic entry in application: '+str(obj))
        declared = set()
        for line in all_records[obj]:
            kind, rest = line.split(' ', 1)
            if kind == 'I':
                signature = rest
                require(settings.get('ENCBOUND_CALLBACKS') == '1', 'indirect call without callbacks')
            else:
                require(kind in ('R', 'D', 'A'), 'unknown ABI record')
                name, signature = rest.split(' ', 1)
                require(re.fullmatch(r'__encbound_va_[0-9a-f]{32}_.+', name), 'invalid private name')
                fingerprint = hashlib.md5(signature.encode()).hexdigest()
                require(name.startswith(PREFIX+fingerprint+'_'), 'private signature fingerprint mismatch')
                require(name not in signatures or signatures[name] == signature, 'conflicting ABI signatures')
                signatures[name] = signature
                declared.add(name)
                if kind == 'A':
                    require(settings.get('ENCBOUND_CALLBACKS') == '1', 'function address without callbacks')
                if kind == 'D' and name in definitions[obj]:
                    owners.setdefault(name, []).append(obj)
            require(signature.startswith('encbound-va-v1:'+profile+':'), 'ABI version/profile mismatch')
        actual = {n for n in definitions[obj]|references[obj] if n.startswith(PREFIX)}
        require(actual <= declared, 'private symbol lacks compiler ABI record: '+str(obj))
    require(len(profiles) == 1, 'mixed application profiles')
    required = {n for obj in app for n in references[obj] if n.startswith(PREFIX)}
    # Address-taken definitions with local linkage also need an actual owner;
    # match per object because local names may repeat across translation units.
    for obj in app:
        for name in definitions[obj]:
            if name.startswith(PREFIX):
                require(obj in owners.get(name, []), 'definition lacks ownership record: '+name)
    for name in required:
        # A local definition cannot resolve another object's undefined symbol.
        global_owners = [obj for obj in owners.get(name, [])
                         if name in subprocess.check_output(['nm', '-g', '--defined-only', str(obj)], text=True).split()]
        require(len(global_owners) == 1, 'missing or duplicate application definition: '+name)
    final = symbols(image, '--defined-only')
    require(required <= final, 'private implementation absent from final image')
    print('APPLICATION VARIADIC CALLBACK ABI / OWNERSHIP PASS')
