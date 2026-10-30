#!/usr/bin/env python3
"""Require the exact instrumented sk-sgx closure, bridge and SDK domains."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from probe import HERE, ROOT, UNITS, MAPPINGS, sha
sys.path.insert(0,str(ROOT/'tools'))
sys.path.insert(0,str(ROOT/'apps'))
from audit_app_globals import audit as ownership
from encbound_inventory import get_marker
from check_sdk_pins import SDK_BINARIES, CXX_GUARD_ARCHIVE_SHA256
from four_app_audit import signed_input


def names(p,*flags):
    return {x.split()[-1] for x in subprocess.check_output(['nm',*flags,str(p)],text=True).splitlines() if x.split()}


def audit(out):
    out=out.resolve();r=json.loads((out/'build.json').read_text());q=json.loads((out/'probe.json').read_text());p=r['profile']
    app=list(map(Path,r['app_objects']));trusted=list(map(Path,r['trusted_objects']))
    assert len(app)==len(UNITS)==10 and len(app)==len(set(app))
    assert q['profile']==p and q['admission_passed']
    assert '-fno-vectorize' in q['frontend_flags'] and '-fno-slp-vectorize' in q['frontend_flags']
    assert q['adapter_mappings']==MAPPINGS
    assert q['source']==json.loads((HERE/'pins.json').read_text())
    for n,h in q['prepared'].items():assert sha(out/'prepared'/n)==h,'prepared source drift: '+n
    original=(HERE/'upstream/enclave.c').read_text()
    assert (out/'prepared/enclave.c').read_text()==original.replace('malloc(aadlen)','malloc(aadlen ? aadlen : 1)')
    for n,h in {**q['inputs'],**r['inputs'],**r['artifacts']}.items():assert sha(n)==h,'input/artifact drift: '+n
    for t in r['trusted_units']:
        assert sha(t['object'])==t['sha256']
        for n,h in t['inputs'].items():assert sha(n)==h,'trusted input drift: '+n
    signed_input(Path(r['image']),Path(r['signed']))
    ownership(Path(r['signed']),app,trusted,out/'enclave/enclave.map')
    defs=set().union(*(names(a,'--defined-only') for a in app))
    globaldefs=set().union(*(names(a,'-g','--defined-only') for a in app))-{'__encbound_instrumented'}
    trusteddefs=set().union(*(names(a,'-g','--defined-only') for a in trusted))
    assert not globaldefs&trusteddefs
    bridge=json.loads((out/'generated/boundary-manifest.json').read_text())
    assert bridge['profile']==p
    assert bridge['ecalls']==['ecall_sk_get_key_handle_len_ed25519','ecall_sk_enroll_ed25519','ecall_sk_sign_ed25519']
    assert bridge['ocalls']==['ocall_puts']
    for n,h in bridge['inputs'].items():assert sha(n)==h,'bridge input drift: '+n
    for n,h in bridge['outputs'].items():assert sha(out/'generated'/n)==h,'bridge output drift: '+n
    allowed=defs|{n for n in trusteddefs if n.startswith('encbound_')}|set(bridge['trusted_ocalls'])
    allowed|={'__stack_chk_fail','memcpy','memmove','memset'}
    if p=='BASELINE':allowed|=set(MAPPINGS)|{'malloc','free','strlen','abort'}
    preset=dict(re.findall(r'^export (ENCBOUND_\w+)=(\S+)$',(ROOT/'config/integration.env').read_text(),re.M));preset.pop('ENCBOUND_WRITABLE_GLOBALS')
    rows=[]
    for obj,original in zip(app,map(Path,r['original_objects'])):
        assert get_marker(obj)==(None if p=='BASELINE' else p)
        u=json.loads(original.with_suffix('.integration.json').read_text())
        assert u['settings']['ENCBOUND_PROFILE']==p
        expected_flags = q['frontend_flags']
        if u['settings']['ENCBOUND_APP_ERRNO'] == '1':
            expected_flags = ['-I'+str(ROOT/'include/encbound_app_libc'),
                              '-I'+str(ROOT/'include'), *expected_flags]
        assert u['frontend_flags'] == expected_flags, 'frontend flag drift: '+str(obj)
        for n,v in preset.items():assert u['settings'].get(n)==v,'preset mismatch: '+str(obj)+' '+n
        for n,h in u['inputs'].items():assert sha(n)==h,'compilation input drift: '+n
        assert sha(original)==u['object_sha256']
        for key,suffix in [('input_ir_sha256','.input.ll'),('checked_ir_sha256','.checked.ll')]:assert sha(original.with_suffix(suffix))==u[key]
        placement=json.loads(Path(str(obj)+'.ownership.json').read_text())
        assert placement['input_sha256']==u['object_sha256'] and placement['output_sha256']==sha(obj)
        unknown=names(obj,'--undefined-only')-allowed
        assert not unknown,'unknown application external '+str(obj)+': '+str(sorted(unknown))
        ir=original.with_suffix('.checked.ll').read_text()
        if p!='BASELINE':
            assert not any(re.search(r'@'+raw+r'\(',l) and not l.startswith('declare ') for raw in MAPPINGS for l in ir.splitlines()),'raw SDK service survivor'
        rows.append(dict(object=str(obj),sha256=sha(obj),checks=ir.count('call i64 @encbound_require')))
    # Every admitted crypto name has an actual application definition. The
    # compiler may normalize public aliases only through the enabled ABI modes.
    for n in q['definitions']:assert n in globaldefs,'missing application definition '+n
    archives={Path(l[5:]) for l in (out/'enclave/enclave.map').read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.a')}
    assert {a.name for a in archives}=={'libsgx_trts_sim.a','libsgx_tstdc.a','libsgx_tcxx.a','libsgx_tcrypto.a','libsgx_tservice_sim.a'}
    for a in archives:
        expected=CXX_GUARD_ARCHIVE_SHA256 if a.name=='libsgx_tcxx.a' else SDK_BINARIES['lib64/'+a.name]
        assert sha(a)==expected
        assert not globaldefs&names(a,'-g','--defined-only'),'application definition collides with SDK'
    result=dict(profile=p,mode='SDK SIM',objects=rows,application_checks=sum(a['checks'] for a in rows),
                archives={str(a):sha(a) for a in sorted(archives)},loaded_permissions='separate host execution check')
    (out/'inventory.json').write_text(json.dumps(result,indent=2)+'\n')
    print('SK-SGX COMPLETE OWNERSHIP/CLOSURE AUDIT PASS',p)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--build',type=Path,required=True)
    audit(ap.parse_args().build)
