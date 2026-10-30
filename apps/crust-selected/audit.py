#!/usr/bin/env python3
"""Closed application/SDK inventory; adapted from the local STL service audit."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from check_early_bootstrap import audit as bootstrap_audit
from check_sdk_pins import SDK_BINARIES, CXX_GUARD_ARCHIVE_SHA256
from encbound_inventory import get_marker


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def nm(obj, *flags):
    return {line.split()[-1] for line in subprocess.check_output(['nm', *flags, str(obj)], text=True).splitlines()
            if line.strip() and not line.endswith(':')}


def global_definitions(obj):
    return nm(obj, '-g', '--defined-only')-{'__encbound_instrumented'}


def audit(out):
    out = Path(out)
    build = json.loads((out/'build.json').read_text())
    profile = build['profile']
    app, trusted = [list(map(Path, build[key])) for key in ('app', 'trusted')]
    lib = Path(build['library'])
    if sha(lib/'build.json') != build['library_manifest_sha256']:
        raise ValueError('library manifest changed')
    library = json.loads((lib/'build.json').read_text())
    prepared = Path(build['prepared_manifest'])
    if sha(prepared) != build['prepared_manifest_sha256'] or library['source_inventory'] != json.loads(prepared.read_text()):
        raise ValueError('prepared library configuration changed')
    if sha(lib/'libencbound_cxx.a') != library['archive_sha256']:
        raise ValueError('private library archive changed')
    for key in ('input_hashes', 'tool_hashes'):
        for path, expected in build[key].items():
            if sha(path) != expected:
                raise ValueError('recipe/tool input drift: '+path)
    if library['profile'] != profile or library['cxx_eh']:
        raise ValueError('private library profile/ABI mismatch')
    if not set(library['objects']) <= set(build['app']) or len(app) != 33:
        raise ValueError('selected application/library object closure mismatch')

    definitions = set().union(*(nm(obj, '--defined-only') for obj in app))
    app_globals = set().union(*(global_definitions(obj) for obj in app))
    trusted_globals = set().union(*(global_definitions(obj) for obj in trusted))
    if app_globals & trusted_globals:
        raise ValueError('application/trusted symbol collision')
    if not {'ecall_safe_store2', 'ecall_restore_from_upgrade', 'crust_selected_snapshot',
            'app_serial_mutex_lock', 'app_serial_mutex_unlock'} <= definitions:
        raise ValueError('missing selected application definition')
    forbidden = {'sgx_thread_mutex_lock', 'sgx_thread_mutex_unlock', 'id_restore_from_upgrade'}
    if forbidden & set().union(*(nm(obj, '-g') for obj in app)):
        raise ValueError('unexpected raw mutex/real restore application reference')
    services = {'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memmove', 'memset', 'memcmp',
                'strlen', 'strcmp', 'strncpy', 'strncat', 'strnlen'}
    adapters = {'encbound_'+name for name in services}|{
        'encbound_require', 'encbound_stack_mint', 'encbound_global_cap', 'encbound_early_bootstrap'}
    adapters |= {name for name in trusted_globals if name.startswith('encbound_cxx_')}
    allowed = definitions | adapters | {'__stack_chk_fail', 'memcpy', 'memmove', 'memset'}
    if profile == 'BASELINE':
        allowed |= services | {'__cxa_atexit', '__dso_handle', '__cxa_guard_acquire',
                                '__cxa_guard_release', '__cxa_guard_abort'}
    units = []
    for obj in app:
        if get_marker(obj) != (None if profile == 'BASELINE' else profile):
            raise ValueError('application profile/domain mismatch: '+str(obj))
        undefined = nm(obj, '--undefined-only')
        if undefined-allowed:
            raise ValueError('unknown application external: '+str(undefined-allowed))
        if any(name.startswith('__encbound_abi_') and name not in definitions for name in undefined):
            raise ValueError('unresolved private application ABI')
        unit = json.loads(obj.with_suffix('.integration.json').read_text())
        placement = json.loads(Path(str(obj)+'.ownership.json').read_text())
        settings = unit['settings']
        if settings['ENCBOUND_PROFILE'] != profile or settings['ENCBOUND_INTEGRATION_PRESET'] != 'all-compat-v1':
            raise ValueError('application preset mismatch')
        for feature in ('CALLBACKS', 'AGGREGATE_ABI', 'CXX_ALLOCATIONS', 'ATOMICS', 'VIRTUALS', 'VARIADICS',
                        'PROTECTED_GLOBALS', 'CXX_LIFECYCLE', 'VLA', 'APP_ERRNO'):
            if settings['ENCBOUND_'+feature] != '1':
                raise ValueError('feature mismatch: '+feature)
        if unit['object_sha256'] != placement['input_sha256'] or sha(obj) != placement['output_sha256']:
            raise ValueError('compilation/placement identity mismatch')
        for path, expected in unit['inputs'].items():
            if sha(path) != expected:
                raise ValueError('application compilation input drift: '+path)
        if unit['checked_ir_sha256'] != sha(obj.with_suffix('.checked.ll')):
            raise ValueError('checked IR changed')
        ir = obj.with_suffix('.checked.ll').read_text()
        if profile != 'BASELINE':
            for line in ir.splitlines():
                if line.startswith('declare '): continue
                if any(re.search('@'+name+r'\b', line) for name in services):
                    raise ValueError('raw application service use: '+line)
            if re.search(r'\b(?:sret|byval)\(', ir):
                raise ValueError('implicit private ABI survivor')
        units.append(dict(object=str(obj), sha256=sha(obj), undefined=sorted(undefined),
            compilation_sha256=sha(obj.with_suffix('.integration.json')),
            placement_sha256=sha(Path(str(obj)+'.ownership.json'))))
    for obj in trusted:
        record = json.loads(obj.with_suffix('.trusted.json').read_text())
        if sha(obj) != record['object_sha256']:
            raise ValueError('trusted object drift: '+str(obj))
        for path, expected in record['inputs'].items():
            if sha(path) != expected:
                raise ValueError('trusted compilation input drift: '+path)
        if any('serial_mutex_redirect.h' in arg for arg in record['command']):
            raise ValueError('application mutex redirect in trusted compilation')

    archives = {Path(line[5:]) for line in (out/'enclave.map').read_text().splitlines()
                if line.startswith('LOAD ') and line.endswith('.a')}
    expected_archives = {'libsgx_tcxx.a':CXX_GUARD_ARCHIVE_SHA256,
                        **{Path(path).name:h for path,h in SDK_BINARIES.items() if path.endswith('.a')}}
    if {path.name for path in archives} != set(expected_archives):
        raise ValueError('SDK archive closure mismatch')
    for archive in archives:
        if sha(archive) != expected_archives[archive.name]:
            raise ValueError('SDK archive identity mismatch')
        if app_globals & global_definitions(archive):
            raise ValueError('application symbol overlaps raw SDK archive')

    source = Path(build['source'])
    body = (source/'selected.cpp').read_text().split('crust_status_t ecall_safe_store2(', 2)[2]
    body = 'crust_status_t ecall_safe_store2('+body.strip()
    if hashlib.sha256(body.encode()).hexdigest() != build['selected_body_sha256']:
        raise ValueError('selected upstream body changed')
    xml = ET.parse(out/'final.xml').getroot()
    if xml.findtext('TCSNum') != '1' or xml.findtext('TCSPolicy') != '0':
        raise ValueError('serial SDK configuration changed')
    manifest = json.loads((out/'generated/boundary-manifest.json').read_text())
    if manifest['profile'] != profile:
        raise ValueError('bridge profile mismatch')
    for path, expected in manifest['inputs'].items():
        if sha(path) != expected: raise ValueError('bridge input drift: '+path)
    for path, expected in manifest['outputs'].items():
        if sha(out/'generated'/path) != expected: raise ValueError('bridge output drift: '+path)
    bridge_text = (out/'generated/enclave_t.c').read_text()
    if profile != 'BASELINE' and (bridge_text.count('status = encbound_bridge_enter();') != 4 or
                                  bridge_text.count('encbound_boundary_release();') != 4):
        raise ValueError('selected protected entries lack complete serial admission')
    if profile == 'BASELINE' and not all(build['baseline_stock_equal'].values()):
        raise ValueError('BASELINE differs from stock Intel generator')
    ownership_audit(out/'enclave.so', app, trusted, out/'enclave.map',
                    bridge_manifests=[out/'generated/boundary-manifest.json'])
    ownership_audit(out/'enclave.signed.so', app, trusted, out/'enclave.map',
                    bridge_manifests=[out/'generated/boundary-manifest.json'])
    if profile != 'BASELINE': bootstrap_audit(out/'enclave.signed.so')
    result = dict(profile=profile, mode='SDK SIM', base=build['base'], application=units,
        trusted={str(obj):sha(obj) for obj in trusted}, archives={str(path):sha(path) for path in archives},
        signed_sha256=sha(out/'enclave.signed.so'), map_sha256=sha(out/'enclave.map'),
        serial_tcs=1, entries=4, real_restore=False)
    (out/'inventory.json').write_text(json.dumps(result, indent=2)+'\n')
    print('CRUST SELECTED CLOSED INVENTORY PASS', profile, build['base'], flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    audit(parser.parse_args().build.resolve())
