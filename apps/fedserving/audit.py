#!/usr/bin/env python3
"""Complete source/object/library/bridge/SDK audit for this combiner recipe."""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'apps'))
sys.path.insert(0, str(ROOT/'tools'))
from four_app_audit import sha, require, nm, loads, signed_input
from audit_app_globals import audit as ownership
from encbound_inventory import get_marker
from check_sdk_pins import SDK_BINARIES, CXX_GUARD_ARCHIVE_SHA256

def audit(build, profile, base, sdk, *, inputs=None):
    def input_matches(path, digest):
        actual = (inputs or {}).get(str(path), {}).get(digest, path)
        return sha(actual) == digest
    b = build.resolve()
    e = b/'enclave'
    config = json.loads((b/'build-config.json').read_text())
    require(config['app'] == 'fedserving' and config['profile'] == profile and
            config['base'] == base and config['codegen'] == '-O2', 'configuration mismatch')
    prepared = json.loads((b/'prepared/prepared.json').read_text())
    pins = json.loads((ROOT/'apps/fedserving/pins.json').read_text())
    require(prepared['revision'] == pins['revision'] and prepared['upstream_hashes'] == pins['files'], 'source pin mismatch')
    for name, digest in prepared['prepared_hashes'].items():
        require(sha(b/name) == digest, 'prepared input drift: '+name)
    library = json.loads((b/'libc-format/build.json').read_text())
    require(library['profile'] == profile and library['callers'] ==
            {str(b/'prepared/Enclave.cpp'):sha(b/'prepared/Enclave.cpp')}, 'library caller/profile drift')
    for name, digest in library['prepared_hashes'].items():
        require(sha(b/'libc-format/source'/name) == digest, 'library source drift')
    archive = b/'libc-format/libencbound_format.a'
    require(sha(archive) == library['archive_sha256'], 'library archive drift')
    libobjects = list(map(Path, library['objects']))
    require(subprocess.check_output(['ar','t',archive], text=True).splitlines() ==
            [p.name for p in libobjects], 'library membership drift')
    for obj in libobjects:
        require(subprocess.check_output(['ar','p',archive,obj.name]) == obj.read_bytes(), 'library member drift')
    app = [e/'Enclave.o', *libobjects]
    names = ['enclave_t', 'cxx_services']
    if profile != 'BASELINE':
        names += 'early_bootstrap boundary_support platform_layout allocations allocator adapters cxx_lifecycle'.split()
        names += ['check_core'] if config['trusted_core'] == 'fused' else ['siphash','runtime','capability']
    trusted = [e/(n+'.o') for n in names]
    require(set(loads(b,'.o')) == {p.resolve() for p in app+trusted}, 'linked object inventory mismatch')
    signed_input(e/'enclave.so', e/'enclave.signed.so')
    ownership(e/'enclave.signed.so', app, trusted, e/'enclave.map')
    definitions = set().union(*(nm(p,'--defined-only') for p in app))
    appdefs = set().union(*(nm(p,'-g','--defined-only') for p in app))-{'__encbound_instrumented'}
    trusteddefs = set().union(*(nm(p,'-g','--defined-only') for p in trusted))
    require(not appdefs & trusteddefs, 'application/trusted definition collision')
    bridge = json.loads((b/'generated/boundary-manifest.json').read_text())
    require(bridge['profile'] == profile and bridge['ecalls'] == ['combine_result'] and
            bridge['ocalls'] == ['ocall_print'] and bridge['user_check_ecalls'] ==
            {'combine_result':['input','output']}, 'boundary inventory mismatch')
    allowed = definitions | {n for n in trusteddefs if n.startswith('encbound_')} | set(bridge['trusted_ocalls'])
    allowed |= {'__stack_chk_fail','memcpy','memmove','memset'}
    if profile == 'BASELINE':
        allowed |= {'malloc','calloc','free','realloc','strlen','strcmp','strncmp','strncpy','strnlen','memcmp','abort'}
    preset = dict(re.findall(r'^export (ENCBOUND_\w+)=(\S+)$', (ROOT/'config/integration.env').read_text(), re.M))
    preset.pop('ENCBOUND_WRITABLE_GLOBALS')
    units = []
    for obj in app:
        require(get_marker(obj) == (None if profile == 'BASELINE' else profile), 'profile marker mismatch')
        unit = json.loads(obj.with_suffix('.integration.json').read_text())
        require(unit['settings']['ENCBOUND_PROFILE'] == profile, 'manifest profile mismatch')
        for key, value in preset.items():
            require(unit['settings'].get(key) == value, 'preset mismatch: '+key)
        for path, digest in unit['inputs'].items():
            require(input_matches(path, digest), 'compiler input drift: '+path)
        for key, suffix in (('input_ir_sha256','.input.ll'),('checked_ir_sha256','.checked.ll')):
            require(sha(obj.with_suffix(suffix)) == unit[key], 'retained IR drift')
        placement = json.loads(Path(str(obj)+'.ownership.json').read_text())
        require(placement['input_sha256'] == unit['object_sha256'] and
                placement['output_sha256'] == sha(obj), 'compilation/placement chain mismatch')
        require(not nm(obj,'--undefined-only')-allowed, 'unknown application externals: '+
                str(sorted(nm(obj,'--undefined-only')-allowed)))
        units.append(dict(object=str(obj), sha256=sha(obj), settings=unit['settings']))
    archives = loads(b,'.a')
    expected = {'libsgx_trts_sim.a','libsgx_tstdc.a','libsgx_tcrypto.a','libsgx_tservice_sim.a','libsgx_tcxx.a'}
    require({p.name for p in archives} == expected and len(archives) == len(expected), 'SDK archive closure mismatch')
    for path in archives:
        digest = CXX_GUARD_ARCHIVE_SHA256 if path.name == 'libsgx_tcxx.a' else SDK_BINARIES['lib64/'+path.name]
        require(sha(path) == digest, 'SDK archive drift')
        require(not appdefs & nm(path,'-g','--defined-only'), 'application/SDK symbol collision')
    link = json.loads((b/'link-record.json').read_text())
    require(link['map_sha256'] == sha(e/'enclave.map') and link['image_sha256'] == sha(e/'enclave.so'), 'link drift')
    require(set(link['objects']) == {str(p.resolve()) for p in app+trusted}, 'link record inventory mismatch')
    for path, digest in {**link['objects'], **link['dependencies']}.items():
        require(input_matches(path, digest), 'linked input drift: '+path)
    for path, digest in bridge['inputs'].items():
        require(input_matches(path, digest), 'bridge input drift')
    for name, digest in bridge['outputs'].items():
        require(sha(b/'generated'/name) == digest, 'bridge output drift')
    subprocess.run(['python3', ROOT/'tools/sgx_metadata.py', 'verify', '--signed', e/'enclave.signed.so',
                    '--base', base, '--size', (b/'extent').read_text().strip()], check=True)
    if profile != 'BASELINE':
        subprocess.run(['python3', ROOT/'tools/check_early_bootstrap.py', e/'enclave.signed.so'], check=True)
    else:
        stock = b/'stock'
        stock.mkdir(exist_ok=True)
        subprocess.run([sdk/'bin/x64/sgx_edger8r','--trusted','--trusted-dir',stock,
                        '--untrusted','--untrusted-dir',stock,'--search-path',sdk/'include',
                        b/'prepared/Enclave.edl'], check=True)
        for name in ('Enclave_t.c','Enclave_t.h','Enclave_u.c','Enclave_u.h'):
            require((stock/name).read_bytes() == (b/'generated'/name).read_bytes(), 'BASELINE bridge differs from stock')
    result = dict(app='fedserving', mode='SDK SIM', profile=profile, base=base,
                  units=units, signed_sha256=sha(e/'enclave.signed.so'), host_sha256=sha(b/'host/host'),
                  source_revision=pins['revision'], bridge_sha256=sha(b/'generated/boundary-manifest.json'),
                  archives={str(p):sha(p) for p in archives})
    (b/'inventory.json').write_text(json.dumps(result, indent=2)+'\n')
    print('FEDSERVING COMPLETE AUDIT PASS', profile, len(app), 'application objects')
    return result

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--profile',required=True)
    p.add_argument('--base',required=True)
    p.add_argument('--sdk',type=Path,required=True)
    a = p.parse_args()
    audit(a.build,a.profile,a.base,a.sdk)
