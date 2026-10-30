#!/usr/bin/env python3
"""Additional closure checks for this selected SGX-KMS integration."""
import hashlib
import json
from pathlib import Path
import re
import subprocess


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def names(p, option):
    return {line.split()[-1] for line in subprocess.check_output(
        ['nm', option, str(p)], text=True).splitlines() if line.strip()}


def audit(app, trusted, profile, services, boundary):
    definitions = set().union(*(names(p, '--defined-only') for p in app))
    trusted_definitions = set().union(*(names(p, '--defined-only') for p in trusted))
    undefined = set().union(*(names(p, '--undefined-only') for p in app))-definitions
    service_names = {('kms_' if profile == 'BASELINE' else 'encbound_kms_')+n for n in services}
    assert service_names <= trusted_definitions
    assert not any(n.startswith(('sgx_', 'kms_', 'encbound_kms_')) for n in definitions)
    ordinary = {'malloc', 'realloc', 'free', 'memcpy', 'memmove', 'memset', 'memcmp', 'strlen', 'strnlen'}
    allowed = service_names|{'__stack_chk_fail', 'encbound_cxx_fail', 'ocall_print_string'}
    allowed |= ordinary if profile == 'BASELINE' else {
        'encbound_'+n for n in ordinary}|{'encbound_require', 'encbound_stack_mint', 'encbound_global_cap',
                                       'memcpy', 'memmove', 'memset'}
    assert undefined <= allowed, sorted(undefined-allowed)
    assert allowed-{'__stack_chk_fail', 'memcpy', 'memmove', 'memset'} <= trusted_definitions if profile != 'BASELINE' else True
    records = [json.loads(p.with_suffix('.integration.json').read_text()) for p in app]
    assert all(r['settings'] == records[0]['settings'] for r in records)
    assert records[0]['settings']['ENCBOUND_CHECK_REUSE'] == 'off'
    assert records[0]['settings']['ENCBOUND_LOCAL_PROOFS'] == '0'
    assert records[0]['settings']['ENCBOUND_FAST_PATHS'] == 'off'
    for obj, record in zip(app, records):
        for suffix, field in (('.input.ll','input_ir_sha256'),('.checked.ll','checked_ir_sha256')):
            assert sha(obj.with_suffix(suffix)) == record[field]
        if profile != 'BASELINE':
            checked = obj.with_suffix('.checked.ll').read_text()
            assert not re.search(r'\b(?:call|invoke)\b[^\n]*@(?:sgx_\w+|kms_\w+|memcpy|memmove|memset)\(', checked), obj
    for obj in trusted:
        assert not obj.with_suffix('.integration.json').exists()
        record = json.loads(obj.with_suffix('.trusted.json').read_text())
        assert sha(obj) == record['object_sha256']
        for source, expected in record['inputs'].items(): assert sha(source) == expected
    bridge = json.loads(boundary.read_text())
    assert set(bridge['application_ecalls']) <= definitions
    assert set(bridge['sdk_ecalls']).isdisjoint(definitions)
    for source, expected in bridge['inputs'].items(): assert sha(source) == expected
    for name, expected in bridge['outputs'].items(): assert sha(boundary.parent/name) == expected
    return dict(application_objects=len(app), trusted_objects=len(trusted),
                application_external_references=sorted(undefined), checked_services=sorted(service_names),
                matched_closure_settings=records[0]['settings'], result='pass')
