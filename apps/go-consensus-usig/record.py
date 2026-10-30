#!/usr/bin/env python3
"""Collect/recheck source, build, closure and runtime evidence for the USIG port."""
import argparse
import json
from pathlib import Path
from prepare import HERE, ROOT, PINS, SOURCE, sha
from build import SDK_SRC
from audit import audit
from run import CONFIGS, NORMAL


def read(path):return json.loads(Path(path).read_text())


def collect(out):
    files=set();rows=[]
    def bind(record):
        for n,h in record.items():
            assert sha(n)==h,'input drift '+n
            files.add(Path(n))
    def commands(items,expected=None):
        for c in items:
            assert sha(c['log'])==c['sha256'],'log drift '+c['log']
            if expected is not None:assert c['returncode']==expected
            files.add(Path(c['log']))
    for name,profile,base in CONFIGS:
        b=out/name;audit(b)
        q,r,inv=[read(b/n) for n in ('probe.json','build.json','inventory.json')]
        assert r['profile']==profile and r['base']==base
        assert NORMAL in (b/'run.log').read_text()
        expected_ranges=4 if profile=='BASELINE' else 6
        assert f'loaded app page permissions: PASS ({expected_ranges} ranges;' in (b/'run.log').read_text()
        commands(q['commands'],0);bind(q['inputs']);bind(r['inputs']);bind(r['artifacts'])
        for n,h in q['prepared'].items():assert sha(b/'prepared'/n)==h;files.add(b/'prepared'/n)
        bridge=read(b/'generated/boundary-manifest.json');bind(bridge['inputs'])
        for n,h in bridge['outputs'].items():assert sha(b/'generated'/n)==h;files.add(b/'generated'/n)
        for obj in map(Path,r['original_objects']):
            unit=read(obj.with_suffix('.integration.json'));bind(unit['inputs'])
            files.update(obj.with_suffix(s) for s in ('.o','.integration.json','.input.ll','.checked.ll','.d'))
        files.update(Path(n+'.ownership.json') for n in r['app_objects'])
        for t in r['trusted_units']:bind(t['inputs'])
        for lib in ('libcxx','libc-format'):
            files.add(b/lib/'build.json');files.add(b/lib/'admitted.txt')
        files.update(b/n for n in ('probe.json','build.json','inventory.json','generated/boundary-manifest.json','admitted.txt'))
        if profile=='BASELINE':
            assert len(q['stock_equality'])==4
            for n,h in q['stock_equality'].items():assert sha(b/'stock'/n)==sha(b/'generated'/n)==h;files.add(b/'stock'/n)
        trace=None
        if profile!='BASELINE':
            trace=read(b/'access.json');assert trace['signed_sha256']==sha(r['signed'])
            assert sha(trace['log'])==trace['log_sha256'];bind(trace['inputs'])
            files.update([b/'access.json',Path(trace['log'])])
        controls=read(b/'controls.json');assert controls['signed_sha256']==sha(r['signed']);bind(controls['inputs'])
        assert len(controls['rows'])==5
        for case in controls['rows']:
            commands([case['direct'],case['debugger']])
            assert sha(case['script'])==case['script_sha256'];files.add(Path(case['script']))
        files.add(b/'controls.json')
        rows.append(dict(configuration=name,profile=profile,base=base,extent=r['extent'],mode='SDK SIM',status='passed',
            build=str(b),normal_ecalls=81,ed25519_verified=19,ecdsa_verified=7,hmac_verified=13,
            application_objects=len(inv['objects']),static_require_calls=inv['application_checks'],
            signed_sha256=sha(r['signed']),inventory=inv,access_trace=trace,controls=controls))
    native=read(out/'native/native.json');bind(native['inputs']);commands(native['commands'],0)
    assert [x['output'].strip() for x in native['rows']]==[
        'usig_adapters_test      81 checks, 0 failures','usig_adapters_test      83 checks, 0 failures']
    for row in native['rows']+[native['helpers']]:assert sha(row['binary'])==row['sha256'];files.add(Path(row['binary']))
    assert 'USIG CRYPTO HELPERS PASS:' in native['helpers']['output'];files.add(out/'native/native.json')
    vector=read(out/'vector-admission/probe.json');bind(vector['inputs']);commands(vector['commands'])
    assert not vector['admission_passed']
    failures={Path(x['source']).stem for x in vector['application_rows'] if x['returncode']}
    assert failures=={'fe25519','crypto_support'}
    diagnostics={n:(out/'vector-admission'/(n+'-application.log')).read_text().splitlines()[0] for n in sorted(failures)}
    assert 'llvm.vector.reduce.and.v4i32' in diagnostics['fe25519'] and 'llvm.vector.reduce.or.v4i32' in diagnostics['crypto_support']
    files.add(out/'vector-admission/probe.json')
    matrix=read(out/'matrix.json');commands(matrix['commands']);bind(matrix['inputs']);files.add(out/'matrix.json')
    assert len(matrix['configurations'])==4
    for c in matrix['commands']:assert c['returncode']==(1 if c['name']=='vector-admission' else 0)
    for n,h in PINS['files'].items():assert sha(SOURCE/n)==h;files.add(SOURCE/n)
    for n in ('sgx_hmac.cpp','sgx_ecc256_ecdsa.cpp','sgx_ecc256.cpp'):
        files.add(SDK_SRC/'sdk/tlibcrypto/ipp'/n)
    files.update(p for p in HERE.iterdir() if p.is_file())
    files.update(ROOT/n for n in ('pass/encbound_cxx_eh.h','tests/cxx-lifecycle/admission.py','apps/sk-sgx/upstream/verify.c'))
    files.update((ROOT/'pass').glob('*.h'));files.add(ROOT/'pass/encbound_pass.cpp')
    regression_root=ROOT/'build/go-consensus-usig'
    regression_specs=[('lifecycle-admission.log','CXX LIFECYCLE ADMISSION PASS 24 controls'),
        ('eh-admission.log','CXX EH ADMISSION/OUTPUT CONTROLS PASS 47'),
        ('lifecycle-sim.log','CXX LIFECYCLE SDK SIM MATRIX PASS 16'),
        ('pass-regression.log','instrumented object rejected from trusted domain')]
    regressions=[]
    for n,expected in regression_specs:
        f=regression_root/n;assert expected in f.read_text();files.add(f)
        regressions.append(dict(log=str(f),sha256=sha(f),checked_summary=expected))
    return dict(date='2026-10-21',application=PINS['repository'],revision=PINS['revision'],source=PINS,
        scope='five-entry USIG component, serial direct-ECALL oracle; not Go/cgo or distributed consensus',
        preset='all-compat-v1',application_frontend='O2; scalar USIG and crypto; C99 crypto / C++17 caller; no EH',
        codegen='O2; reuse/proofs/fast paths off',sdk_sim=rows,native=native,
        vector_admission=dict(status='rejected',diagnostics=diagnostics),regressions=regressions,
        totals=dict(configurations=4,normal_ecalls=324,ed25519_verified=76,ecdsa_verified=28,hmac_verified=52,
            application_objects=183,terminal_or_malformed_case_rows=20),
        core_change='Restore ordinary owned destructor registration in no-EH output verification; EH wrapper requirement retained.',
        limits=['SDK SIM and native stand-ins are distinct; no hardware/performance',
            'Explicit C-language/linkage, helper, formatter-symbol and SDK-import build adaptations',
            'Default vectorized intrinsic forms remain unsupported; matched scalar frontend used',
            'RADIX_ONLY accepts the one-past NUL write; MAC27 rejects TAG in the observed runs',
            'libc++ assertion and terminal allocation controls are not spatial protection',
            'Automatic SIM destructor execution, full resource accounting, Go/cgo, distributed concurrency, rollback and protocol security unestablished'],
        retained={str(p):sha(p) for p in sorted(files)})


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--build-root',type=Path)
    ap.add_argument('--output',type=Path);ap.add_argument('--verify',type=Path);a=ap.parse_args()
    if a.verify:
        r=read(a.verify)
        for n,h in r['retained'].items():assert sha(n)==h,'retained drift '+n
        for row in r['sdk_sim']:
            audit(Path(row['build']));assert read(Path(row['build'])/'inventory.json')==row['inventory']
        print('USIG EVIDENCE REPLAY PASS',len(r['retained']),'hashes; four complete closure audits')
    else:
        assert a.build_root and a.output
        result=collect(a.build_root.resolve());a.output.write_text(json.dumps(result,indent=2)+'\n')
        print('USIG EVIDENCE COLLECTED',result['totals'])

if __name__=='__main__':main()
