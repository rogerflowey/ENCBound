#!/usr/bin/env python3
"""Mandatory closed wallet inventory; markers supplement, not prove, coverage."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from encbound_inventory import get_marker
from check_sdk_pins import SDK_BINARIES
from audit_app_globals import object_symbols

APP = {'enclave.o', 'sealing.o'}
TRUSTED = {'enclave_t.o'}
RUNTIME = {'sdk_adapters.o', 'siphash.o', 'runtime.o', 'capability.o',
           'allocations.o', 'allocator.o', 'adapters.o', 'platform_layout.o',
           'boundary_support.o'}
SERVICES = {'malloc', 'free', 'strlen', 'strcmp', 'strncpy', 'sgx_seal_data',
            'sgx_unseal_data', 'ocall_is_wallet', 'ocall_save_wallet',
            'ocall_load_wallet', 'ocall_debug_print'}
# The application owns original ECALL names; Intel bridges call them directly.
PRIVATE_PREFIX = ''
PUBLIC_ECALLS = {'ecall_create_wallet', 'ecall_show_wallet',
                 'ecall_change_master_password', 'ecall_add_item',
                 'ecall_remove_item'}
PRIVATE_ECALLS = {PRIVATE_PREFIX + name for name in PUBLIC_ECALLS}
APP_FUNCTIONS = PRIVATE_ECALLS | {'seal_wallet', 'unseal_wallet'}

def nm(path, option):
    lines = subprocess.check_output(['nm', option, str(path)], text=True).splitlines()
    return {line.split()[-1] for line in lines if len(line.split()) >= 2}

def audit_application_definitions(obj):
    """Retain the no-app-data inventory while admitting exact compiler markers."""
    definitions = nm(obj, '--defined-only')
    metadata = definitions & {'__encbound_lifecycle_v1', '__encbound_globals_v1'}
    if metadata:
        unit = json.loads(obj.with_suffix('.integration.json').read_text())
        sections = subprocess.check_output(['readelf', '-SW', str(obj)], text=True)
        abi = re.findall(r'\[\s*(\d+)\]\s+\.encbound\.abi\s+PROGBITS\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+([A-Za-z]+)', sections)
        if (not abi or sum(int(s[2], 16) for s in abi) != 8*len(metadata) or
                any('W' in s[3] or 'X' in s[3] for s in abi) or
                re.search(r'\s\.rela?\.encbound\.abi\s', sections)):
            raise ValueError(f'{obj.name}: invalid compiler ABI metadata section')
        raw = obj.read_bytes()
        payloads = {s[0]: raw[int(s[1], 16):int(s[1], 16)+int(s[2], 16)] for s in abi}
        symbols = [s for s in object_symbols(obj) if s['name'] in metadata]
        if len(symbols) != len(metadata) or {s['name'] for s in symbols} != metadata:
            raise ValueError(f'{obj.name}: compiler ABI marker is not an exact data object')
        occupied = set()
        for symbol in symbols:
            setting = ('ENCBOUND_CXX_LIFECYCLE' if symbol['name'] == '__encbound_lifecycle_v1'
                       else 'ENCBOUND_PROTECTED_GLOBALS')
            payload = payloads.get(symbol['section'], b'')
            span = {(symbol['section'], i) for i in range(symbol['value'], symbol['value']+8)}
            if (unit['settings'].get(setting) != '1' or symbol['size'] != 8 or
                    payload[symbol['value']:symbol['value']+8] != (1).to_bytes(8, 'little') or
                    span & occupied):
                raise ValueError(f'{obj.name}: unexpected compiler ABI metadata')
            occupied |= span
    unknown = definitions - APP_FUNCTIONS - {'__encbound_instrumented'} - metadata
    if unknown:
        raise ValueError(f'{obj.name}: unclassified application definitions {sorted(unknown)}')

def audit(build, profile, *, bridge_inputs=None):
    """Audit live inputs by default; replay may supply exact retained files."""
    protected = profile != 'BASELINE'
    directory = build / 'enclave'
    trusted = TRUSTED | (RUNTIME if protected else set())
    objects = APP | trusted
    # Linker map is the authoritative set of actual direct input objects.
    loads = {Path(line.split(maxsplit=1)[1]).resolve()
             for line in (directory / 'enclave.map').read_text().splitlines()
             if line.startswith('LOAD ') and line.endswith('.o')}
    if loads != {(directory / name).resolve() for name in objects}:
        raise ValueError('linked object inventory differs from declared app/trusted domains')
    allowed = {'__stack_chk_fail', 'seal_wallet', 'unseal_wallet',
               'memcpy', 'memmove', 'memset'}
    ocalls = {name for name in SERVICES if name.startswith('ocall_')}
    allowed |= ({'encbound_' + name for name in SERVICES - ocalls} | ocalls |
                {'encbound_require', 'encbound_stack_mint'} if protected else SERVICES)
    symbols = nm(directory / 'enclave.so', '--defined-only')
    records = []
    for name in sorted(objects):
        obj = directory / name
        marker = get_marker(obj)
        expected = profile if protected and name in APP else None
        if marker != expected: raise ValueError(f'{name}: marker {marker!r} != {expected!r}')
        if name in APP:
            unknown = nm(obj, '--undefined-only') - allowed
            if unknown: raise ValueError(f'{name}: unapproved references {sorted(unknown)}')
            ir = obj.with_suffix('.checked.ll').read_text()
            if protected and 'call ' in ir:
                # Raw memory symbols can only arise later, from already checked
                # intrinsics. Source-level raw calls must have been redirected.
                if re.search(r'\bcall\b[^\n]*@(?:' + '|'.join((SERVICES - ocalls) | {'memcpy', 'memmove', 'memset'}) + r')\(', ir):
                    raise ValueError(f'{name}: raw service call survives in final IR')
            for symbol in nm(obj, '--undefined-only'):
                if symbol not in symbols: raise ValueError(f'{name}: missing final symbol {symbol}')
            # This wallet currently has no application data globals or literals.
            # If that changes, fail until app-owned COMPAT sections are established.
            # The all-compat compiler emits ABI metadata even in a TU without
            # application globals/startup lists. Accept only the exact retained
            # constant markers, never a new application data object.
            audit_application_definitions(obj)
        records.append({'object': name, 'domain': 'application' if name in APP else 'trusted',
                        'profile_marker': marker,
                        'sha256': hashlib.sha256(obj.read_bytes()).hexdigest()})
    # Application symbols are owned by instrumented objects; the sole Intel
    # bridge references them directly. No companion adapter defines/forwards them.
    app_defs = set().union(*(nm(directory / name, '--defined-only') for name in APP))
    if not PUBLIC_ECALLS <= app_defs:
        raise ValueError('application lacks original ECALL definitions')
    bridge_refs = nm(directory / 'enclave_t.o', '--undefined-only')
    if not PUBLIC_ECALLS <= bridge_refs:
        raise ValueError('modified Intel bridge does not call original ECALLs')
    bridge_defs = nm(directory / 'enclave_t.o', '--defined-only')
    if not ocalls <= bridge_defs or PUBLIC_ECALLS & bridge_defs:
        raise ValueError('incorrect bridge symbol ownership')
    manifest = json.loads((build / 'encbound-generated/boundary-manifest.json').read_text())
    if manifest.get('architecture') != 'modified-intel-bridge' or manifest['profile'] != profile:
        raise ValueError('wrong bridge architecture/profile')
    if bridge_inputs is not None and set(bridge_inputs) != set(manifest['inputs']):
        raise ValueError('retained bridge input inventory mismatch')
    for path, expected_hash in manifest['inputs'].items():
        actual = Path(path if bridge_inputs is None else bridge_inputs[path])
        if hashlib.sha256(actual.read_bytes()).hexdigest() != expected_hash:
            raise ValueError('bridge input changed: ' + path)
    for filename in ('enclave_t.c', 'enclave_t.h'):
        if hashlib.sha256((directory / filename).read_bytes()).hexdigest() != manifest['outputs'][filename]:
            raise ValueError('bridge output changed: ' + filename)
    bridge_text = (directory / 'enclave_t.c').read_text()
    if protected:
        if 'encbound_bridge_alloc(' not in bridge_text or 'encbound_bridge_range(' not in bridge_text:
            raise ValueError('missing in-bridge adaptation')
        if not {'encbound_boundary_alloc', 'encbound_require'} <= bridge_refs:
            raise ValueError('bridge object lacks checked runtime calls')
    elif 'encbound_bridge_' in bridge_text:
        raise ValueError('baseline contains protected adaptation')
    # Verify trusted SDK archive members have no application marker.
    archives = {line.split(maxsplit=1)[1] for line in
                (directory / 'enclave.map').read_text().splitlines()
                if line.startswith('LOAD ') and line.endswith('.a')}
    expected_archives = {'libsgx_trts_sim.a', 'libsgx_tservice_sim.a',
                         'libsgx_tstdc.a', 'libsgx_tcrypto.a'}
    if '-HW-' in '-' + build.name + '-':
        expected_archives = {name.replace('_sim.a', '.a') for name in expected_archives}
    if {Path(a).name for a in archives} != expected_archives:
        raise ValueError(f'unexpected SDK archive inventory: {sorted(archives)}')
    for archive in archives:
        sections = subprocess.check_output(['readelf', '-SW', archive], text=True)
        if '.encbound.audit' in sections: raise ValueError(f'instrumented SDK archive: {archive}')
        # Bind the pin hash to the archive the linker actually resolved: the
        # map path, not a default SDK directory. An alternate same-named archive
        # reached through an overridden search path fails here.
        expected_hash = SDK_BINARIES.get('lib64/' + Path(archive).name)
        if expected_hash is None:
            raise ValueError(f'linked SDK archive is not pinned: {archive}')
        if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != expected_hash:
            raise ValueError(f'linked SDK archive hash mismatch: {archive}')
    record = {'profile': profile, 'application_globals': 'none; new definitions fail audit',
              'objects': records, 'sdk_archives': sorted(archives),
              'limitation': 'Object markers alone do not prove individual memory-operation coverage.'}
    (build / 'inventory.json').write_text(json.dumps(record, indent=2) + '\n')
    print(f'WALLET INVENTORY PASS ({profile}, {len(objects)} objects, app globals absent)')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--profile', choices=['BASELINE', 'RADIX_ONLY', 'MAC27'], required=True)
    args = parser.parse_args()
    try: audit(args.build, args.profile)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f'wallet-audit: FAIL: {exc}')
