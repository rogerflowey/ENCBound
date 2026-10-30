#!/usr/bin/env python3
"""Audit exact selected source, entire application closure, bridge and image."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from prepare import HERE, ROOT, PINS, FUNCTIONS, function, sha
from build import SDK

sys.path.insert(0, str(ROOT/'tools'))
sys.path.insert(0, str(ROOT/'apps'))
from audit_app_globals import audit as ownership
from check_early_bootstrap import audit as startup
from check_sdk_pins import SDK_BINARIES, CXX_GUARD_ARCHIVE_SHA256
from encbound_inventory import get_marker
from four_app_audit import signed_input, loads


def names(path, *flags):
    return {line.split()[-1] for line in subprocess.check_output(['nm', *flags, str(path)], text=True).splitlines() if line.split()}


def audit(out):
    out = out.resolve()
    r = json.loads((out/'build.json').read_text())
    q = json.loads((out/'probe.json').read_text())
    prepared = json.loads((out/'prepared.json').read_text())
    appname, profile = r['app'], r['profile']
    assert q['profile'] == profile and q['admission_passed'] and q['source'] == PINS[appname]
    assert prepared['pin'] == PINS[appname] and sha(out/'prepared.json') == q['prepared_record_sha256']
    for name, digest in prepared['files'].items():
        assert sha(Path(prepared['source'])/name) == digest, 'source drift '+name
    for name, digest in prepared['prepared'].items():
        assert sha(out/'prepared'/name) == digest, 'prepared drift '+name
    for name in FUNCTIONS[appname]:
        original = function(Path(prepared['original']).read_text(), name)
        assert original == function((out/'prepared/Enclave.cpp').read_text(), name)
        assert hashlib.sha256(original.encode()).hexdigest() == prepared['function_hashes'][name]
    for name, digest in {**r['inputs'], **r['artifacts']}.items():
        assert sha(name) == digest, 'input drift '+name
    for unit in r['trusted_units']:
        assert sha(unit['object']) == unit['sha256']
        for name, digest in unit['inputs'].items():
            assert sha(name) == digest, 'trusted input drift '+name
    g = out/'generated'
    bridge = json.loads((g/'boundary-manifest.json').read_text())
    assert bridge['profile'] == profile and bridge['architecture'] == 'modified-intel-bridge'
    assert bridge['ecalls'] == FUNCTIONS[appname]+(['diagnostic_fileids'] if appname == 'POSUP' else [])
    assert bridge['ocalls'] == []
    expected_user_check = {'ecall_getPathID': ['output'], 'ecall_setFileIDs': ['fid_arr']} if appname == 'POSUP' else {'ecall_data_preprocess': ['p_datau', 'p_labelu']}
    assert bridge['user_check_ecalls'] == expected_user_check
    for name, digest in bridge['inputs'].items():
        assert sha(name) == digest, 'bridge input drift '+name
    for name, digest in bridge['outputs'].items():
        assert sha(g/name) == digest, 'bridge output drift '+name
    app, trusted = list(map(Path, r['app_objects'])), list(map(Path, r['trusted_objects']))
    expected = [out/'enclave/Enclave.o']
    if appname == 'POSUP':
        expected += [out/'enclave/abs.o']
        library = json.loads((out/'libcxx/build.json').read_text())
        assert library['profile'] == profile and library['callers'] == {str(out/'prepared/Enclave.cpp'): sha(out/'prepared/Enclave.cpp')}
        archive = out/'libcxx/libencbound_cxx.a'
        assert sha(archive) == library['archive_sha256']
        members = list(map(Path, library['objects']))
        assert subprocess.check_output(['ar', 't', archive], text=True).splitlines() == [p.name for p in members]
        for member in members:
            assert subprocess.check_output(['ar', 'p', archive, member.name]) == member.read_bytes()
        expected += members
    assert app == expected and len(app) == len(set(app))
    assert set(loads(out, '.o')) == {p.resolve() for p in app+trusted}
    ownership(Path(r['signed']), app, trusted, out/'enclave/enclave.map')
    signed_input(Path(r['image']), Path(r['signed']))
    if profile != 'BASELINE':
        startup(Path(r['signed']))
    else:
        stock = out/'stock'
        stock.mkdir(exist_ok=True)
        subprocess.run([SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock,
            '--untrusted', '--untrusted-dir', stock, '--search-path', out/'prepared',
            '--search-path', SDK/'include', out/'prepared/Enclave.edl'], check=True)
        for suffix in ('_t.c', '_t.h', '_u.c', '_u.h'):
            assert (stock/('Enclave'+suffix)).read_bytes() == (g/('Enclave'+suffix)).read_bytes()
    definitions = set().union(*(names(p, '--defined-only') for p in app))
    appdefs = set().union(*(names(p, '-g', '--defined-only') for p in app))-{'__encbound_instrumented'}
    trusteddefs = set().union(*(names(p, '-g', '--defined-only') for p in trusted))
    assert not appdefs & trusteddefs, 'app/trusted definition collision'
    allowed = definitions | {n for n in trusteddefs if n.startswith('encbound_')} | set(bridge['trusted_ocalls'])
    allowed |= {'__stack_chk_fail', 'memcpy', 'memmove', 'memset'}
    if profile == 'BASELINE':
        allowed |= {'malloc', 'calloc', 'free', 'realloc', 'memcmp', 'strlen', 'strnlen', 'strcmp', 'strncmp',
            'strncpy', 'abort', 'abs', '__cxa_atexit', '__dso_handle', '__cxa_guard_acquire', '__cxa_guard_release',
            'sgx_read_rand', 'sgx_hmac_sha256_msg'}
    preset = dict(re.findall(r'^export (ENCBOUND_\w+)=(\S+)$', (ROOT/'config/integration.env').read_text(), re.M))
    preset.pop('ENCBOUND_WRITABLE_GLOBALS')
    rows = []
    for obj, original in zip(app, map(Path, r['original_objects'])):
        unit = json.loads(original.with_suffix('.integration.json').read_text())
        place = json.loads(Path(str(obj)+'.ownership.json').read_text())
        assert get_marker(obj) == (None if profile == 'BASELINE' else profile)
        assert unit['settings']['ENCBOUND_PROFILE'] == profile
        for name, value in preset.items():
            assert unit['settings'].get(name) == value, (str(obj), name)
        for name, digest in unit['inputs'].items():
            assert sha(name) == digest, 'unit input drift '+name
        assert place['input_sha256'] == unit['object_sha256'] and place['output_sha256'] == sha(obj)
        if original != obj:
            assert sha(original) == unit['object_sha256']
        for name, suffix in [('input_ir_sha256', '.input.ll'), ('checked_ir_sha256', '.checked.ll')]:
            assert sha(original.with_suffix(suffix)) == unit[name]
        assert not names(obj, '--undefined-only')-allowed, sorted(names(obj, '--undefined-only')-allowed)
        ir = original.with_suffix('.checked.ll').read_text()
        rows.append(dict(object=str(obj), sha256=sha(obj), checks=ir.count('call i64 @encbound_require')))
    archives = loads(out, '.a')
    assert {a.name for a in archives} == {'libsgx_trts_sim.a', 'libsgx_tcxx.a', 'libsgx_tstdc.a', 'libsgx_tcrypto.a', 'libsgx_tservice_sim.a'}
    assert len(archives) == 5
    for archive in archives:
        expected_hash = CXX_GUARD_ARCHIVE_SHA256 if archive.name == 'libsgx_tcxx.a' else SDK_BINARIES['lib64/'+archive.name]
        assert sha(archive) == expected_hash
        assert not appdefs & names(archive, '-g', '--defined-only'), 'app/SDK definition collision'
    subprocess.run(['python3', ROOT/'tools/sgx_metadata.py', 'verify', '--signed', r['signed'],
        '--base', r['base'], '--size', r['extent']], check=True)
    result = dict(app=appname, profile=profile, base=r['base'], mode='SDK SIM', objects=rows,
        signed_sha256=sha(r['signed']), host_sha256=sha(r['host']),
        archives={str(a): sha(a) for a in archives})
    (out/'inventory.json').write_text(json.dumps(result, indent=2)+'\n')
    print('COMPLETE OWNERSHIP/CLOSURE AUDIT PASS', appname, profile, len(app), 'objects')
    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', type=Path, required=True)
    audit(ap.parse_args().build)
