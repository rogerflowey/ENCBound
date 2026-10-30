#!/usr/bin/env python3
"""Audit the complete USIG/application-library closure and trusted boundary."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from prepare import HERE, ROOT, PINS, sha
from build import MAPPINGS, CRYPTO, SDK
sys.path.insert(0,str(ROOT/'tools'))
sys.path.insert(0,str(ROOT/'apps'))
from audit_app_globals import audit as ownership
from check_early_bootstrap import audit as startup
from check_sdk_pins import SDK_BINARIES, CXX_GUARD_ARCHIVE_SHA256
from encbound_inventory import get_marker
from four_app_audit import signed_input


def names(p,*flags):
    return {x.split()[-1] for x in subprocess.check_output(['nm',*flags,str(p)],text=True).splitlines() if x.split()}


def audit(out):
    out=out.resolve();r=json.loads((out/'build.json').read_text());q=json.loads((out/'probe.json').read_text());p=r['profile']
    assert q['profile']==p and q['admission_passed'] and q['source']==PINS
    assert q['adapter_mappings']==MAPPINGS
    for n,h in q['prepared'].items():assert sha(out/'prepared'/n)==h,'prepared drift '+n
    for n,h in {**q['inputs'],**r['inputs'],**r['artifacts']}.items():assert sha(n)==h,'input drift '+n
    for t in r['trusted_units']:
        assert sha(t['object'])==t['sha256']
        for n,h in t['inputs'].items():assert sha(n)==h,'trusted input drift '+n
    g=out/'generated';bridge=json.loads((g/'boundary-manifest.json').read_text())
    assert bridge['profile']==p
    assert set(bridge['ecalls'])=={'ecall_usig_init','ecall_usig_create_ui_sig','ecall_usig_create_ui_mac',
        'ecall_usig_verify_ui_mac','ecall_usig_create_ui_sig_edd25519'}
    assert bridge['ocalls']==['ocall_print_string']
    assert set(bridge['sdk_only'])==set(json.loads((HERE/'boundary-interface.json').read_text())['sdk_only_imports']['sgx_tstdc.edl']['symbols'])
    for n,h in bridge['inputs'].items():assert sha(n)==h,'bridge input drift '+n
    for n,h in bridge['outputs'].items():assert sha(g/n)==h,'bridge output drift '+n
    expected=[out/'enclave'/f'{n}.o' for n in ['usig_enclave',*CRYPTO,'crypto_support']]
    if p!='BASELINE':expected += [out/'enclave/usig_enclave_app.o']
    for lib in ('libcxx','libc-format'):
        librecord=json.loads((out/lib/'build.json').read_text())
        assert librecord['profile']==p and str(out/'prepared/trusted/usig_enclave.cpp') in librecord['callers']
        expected+=list(map(Path,librecord['objects']))
    app=list(map(Path,r['app_objects']));trusted=list(map(Path,r['trusted_objects']))
    assert app==expected and len(app)==len(set(app))
    ownership(Path(r['signed']),app,trusted,out/'enclave/enclave.map')
    signed_input(Path(r['image']),Path(r['signed']))
    if p!='BASELINE':startup(Path(r['signed']))
    defs=set().union(*(names(a,'--defined-only') for a in app))
    globals_=set().union(*(names(a,'-g','--defined-only') for a in app))-{'__encbound_instrumented'}
    trusteddefs=set().union(*(names(t,'-g','--defined-only') for t in trusted))
    assert not globals_&trusteddefs,'application/trusted definition collision'
    allowed=defs|{n for n in trusteddefs if n.startswith('encbound_')}|set(bridge['trusted_ocalls'])
    allowed|={'__stack_chk_fail','memcpy','memmove','memset'}
    if p=='BASELINE':allowed|=set(MAPPINGS)|{'malloc','free','calloc','realloc','memcmp','strlen','strnlen','strncpy',
        'strcmp','strchr','strrchr','strcat','strcpy','abort','__cxa_atexit','__dso_handle','__cxa_guard_acquire','__cxa_guard_release'}
    preset=dict(re.findall(r'^export (ENCBOUND_\w+)=(\S+)$',(ROOT/'config/integration.env').read_text(),re.M));preset.pop('ENCBOUND_WRITABLE_GLOBALS')
    source_flags={x['object']:q['frontend_flags'][x['source']] for x in q['application_rows']}
    rows=[]
    for obj,original in zip(app,map(Path,r['original_objects'])):
        u=json.loads(original.with_suffix('.integration.json').read_text());place=json.loads(Path(str(obj)+'.ownership.json').read_text())
        assert get_marker(obj)==(None if p=='BASELINE' else p)
        assert u['settings']['ENCBOUND_PROFILE']==p
        for n,v in preset.items():assert u['settings'].get(n)==v,(str(obj),n)
        for n,h in u['inputs'].items():assert sha(n)==h,'unit input drift '+n
        assert place['input_sha256']==u['object_sha256'] and place['output_sha256']==sha(obj)
        if original!=obj:assert sha(original)==u['object_sha256']
        for n,suffix in [('input_ir_sha256','.input.ll'),('checked_ir_sha256','.checked.ll')]:assert sha(original.with_suffix(suffix))==u[n]
        if str(original) in source_flags:
            expected_flags = source_flags[str(original)]
            if u['settings']['ENCBOUND_APP_ERRNO'] == '1':
                expected_flags = ['-I'+str(ROOT/'include/encbound_app_libc'),
                                  '-I'+str(ROOT/'include'), *expected_flags]
            assert u['frontend_flags'] == expected_flags, 'frontend flag drift: '+str(obj)
        assert u['settings']['ENCBOUND_CXX_EH'] in (None,'0')
        assert u['settings']['ENCBOUND_KEEP_GEP_FLAGS'] in (None,'0')
        assert u['settings']['ENCBOUND_POST_INSTCOMBINE'] in (None,'0')
        unknown=names(obj,'--undefined-only')-allowed
        assert not unknown,'unknown application calls '+str(obj)+': '+str(sorted(unknown))
        ir=original.with_suffix('.checked.ll').read_text()
        if p!='BASELINE':assert not any(re.search('@'+raw+r'\(',l) and not l.startswith('declare ') for raw in MAPPINGS for l in ir.splitlines())
        rows.append(dict(object=str(obj),sha256=sha(obj),checks=ir.count('call i64 @encbound_require')))
    # Library namespaces and complete object ownership forbid raw SDK C++ fallback.
    archives={Path(l[5:]) for l in (out/'enclave/enclave.map').read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.a')}
    assert {a.name for a in archives}=={'libsgx_trts_sim.a','libsgx_tcxx.a','libsgx_tstdc.a','libsgx_tcrypto.a','libsgx_tservice_sim.a'}
    for a in archives:
        expect=CXX_GUARD_ARCHIVE_SHA256 if a.name=='libsgx_tcxx.a' else SDK_BINARIES['lib64/'+a.name]
        assert sha(a)==expect
        assert not globals_&names(a,'-g','--defined-only'),'app definition collides with SDK'
    (out/'inventory.json').write_text(json.dumps(dict(profile=p,mode='SDK SIM',objects=rows,
        application_checks=sum(x['checks'] for x in rows),archives={str(a):sha(a) for a in sorted(archives)}),indent=2)+'\n')
    print('USIG COMPLETE OWNERSHIP/CLOSURE AUDIT PASS',p,len(app),'objects')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--build',type=Path,required=True);audit(ap.parse_args().build)
