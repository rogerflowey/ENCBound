#!/usr/bin/env python3
"""Collect or replay the bounded sk-sgx native/SIM evidence matrix."""
import argparse
import json
import re
from pathlib import Path
from probe import HERE, ROOT, sha
from audit import audit

CONFIGS = [('BASELINE','BASELINE','0x40000000'),
           ('RADIX_ONLY','RADIX_ONLY','0x40000000'),
           ('MAC27','MAC27','0x40000000'),
           ('MAC27-high','MAC27','0x140000000')]
EXPECTED = 'PASS ecalls=68 verified_signatures=21 provider=original-v4 max_application=4096'


def read(p):
    return json.loads(Path(p).read_text())


def collect(out):
    files = set()
    results = []
    for name, profile, base in CONFIGS:
        build = out/name
        audit(build)
        q, r, inventory = [read(build/n) for n in ('probe.json','build.json','inventory.json')]
        assert r['profile']==profile and r['base']==base
        assert EXPECTED in (build/'run.log').read_text()
        permissions = re.findall(r'loaded app page permissions: PASS \((\d+) ranges;',
                                 (build/'run.log').read_text())
        assert len(permissions)==4 and set(permissions)=={'1'}
        for commands in (q['commands'], read(build/'finish-commands.json')):
            for c in commands:
                assert c['returncode']==0 and sha(c['log'])==c['sha256']
                files.add(Path(c['log']))
        files.update(Path(n) for n in [*q['inputs'], *r['inputs'], *r['artifacts']])
        files.update(build/n for n in ('probe.json','build.json','finish-commands.json',
                     'generated/boundary-manifest.json','sk.edl','boundary-interface.json','admitted.txt',
                     'sizing.xml','final.xml'))
        for obj in map(Path, r['original_objects']):
            for ext in ('.o','.input.ll','.checked.ll','.integration.json','.d'):
                files.add(obj.with_suffix(ext))
            files.add(Path(r['app_objects'][r['original_objects'].index(str(obj))]+'.ownership.json'))
            files.update(Path(n) for n in read(obj.with_suffix('.integration.json'))['inputs'])
        for t in r['trusted_units']:
            files.update(Path(n) for n in t['inputs'])
        trace = None
        if profile!='BASELINE':
            trace = read(build/'access.json')
            assert trace['signed_sha256']==sha(r['signed'])
            assert trace['log_sha256']==sha(trace['log'])
            files.add(build/'access.json')
            files.add(Path(trace['log']))
            files.update(Path(n) for n in trace['inputs'])
        results.append(dict(configuration=name,profile=profile,base=base,extent=r['extent'],
                            mode='SDK SIM',status='passed',direct_ecalls=68,
                            provider_ecalls=3,verified_signatures=21,
                            checks=inventory['application_checks'],inventory=inventory,
                            build=str(build),trace=trace))
    native = read(out/'native/native.json')
    assert [r['output'] for r in native['profiles']]==[
        'sk_sgx_adapters_test    54 checks, 0 failures',
        'sk_sgx_adapters_test    56 checks, 0 failures']
    files.add(out/'native/native.json')
    files.update(Path(n) for n in native['inputs'])
    for c in native['commands']:
        assert c['returncode']==0 and sha(c['log'])==c['sha256']
        files.add(Path(c['log']))
    for r in native['profiles']:
        assert sha(r['binary'])==r['sha256']
        files.add(Path(r['binary']))
    vector = read(out/'vector-admission/probe.json')
    assert not vector['admission_passed']
    failures = [r['unit'] for r in vector['application_rows'] if r['returncode']]
    assert failures==['fe25519','verify']
    diagnostics = {}
    for unit in failures:
        log = out/'vector-admission'/(unit+'-application.log')
        diagnostic = log.read_text().splitlines()[0]
        assert 'ENCBound: unsupported intrinsic' in diagnostic and 'llvm.vector.reduce.' in diagnostic
        diagnostics[unit] = diagnostic
    files.add(out/'vector-admission/probe.json')
    files.update(Path(n) for n in vector['inputs'])
    files.update(Path(c['log']) for c in vector['commands'])
    files.update(p for p in HERE.iterdir() if p.is_file() and p.suffix in ('.py','.c','.h','.json','.xml'))
    vuln = read(out/'vuln.json')
    assert vuln['application']=='mfriedl/sk-sgx'
    assert [r['configuration'] for r in vuln['sim']]==[c[0] for c in CONFIGS]
    assert all(r['cases']['h1']['result']!='' for r in vuln['sim'])
    files.add(out/'vuln.json')
    files.update(Path(n) for n in vuln['retained'])
    result = dict(date='2026-10-21',application='mfriedl/sk-sgx',
                  scope='complete non-debug ten-unit enclave closure; original SK v4 provider',
                  source=read(HERE/'pins.json'),preset='all-compat-v1',
                  frontend='-O2 -fno-vectorize -fno-slp-vectorize',codegen='-O2',
                  sdk_sim=results,native=native,vector_admission=dict(status='rejected',diagnostics=diagnostics),
                  vulnerability=vuln,
                  totals=dict(configurations=4,direct_ecalls=272,provider_ecalls=12,verified_signatures=84),
                  limits=['SDK SIM only; hardware and performance not established',
                          'Default vectorized frontend rejected; matched scalar frontend required',
                          'malloc(0) application adaptation applied identically in all profiles',
                          'Non-debug enclave; no debug formatter or SSH client/server workflow tested',
                          'Valid tagged crypto access and native adapter rejections are separate evidence',
                          'Sealed-handle control: native ASan and BASELINE show the read; RADIX_ONLY/MAC27/MAC27-high reject the 1-byte handle with an attributed adapter RANGE; a 516-byte handle stays in rounded-slot padding and is rejected by the original length check',
                          'No sk-sgx exploit prevention, MAC advantage, temporal safety or crypto assurance claim'],
                  retained={str(p):sha(p) for p in sorted(files)})
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build-root',type=Path)
    ap.add_argument('--output',type=Path)
    ap.add_argument('--verify',type=Path)
    args=ap.parse_args()
    if args.verify:
        record=read(args.verify)
        for n,h in record['retained'].items():
            assert sha(n)==h,'retained input/artifact drift: '+n
        for r in record['sdk_sim']:
            audit(Path(r['build']))
            assert read(Path(r['build'])/'inventory.json')==r['inventory']
        print('SK-SGX EVIDENCE REPLAY PASS',len(record['retained']),'hashes; four complete closure audits')
    else:
        assert args.build_root and args.output, '--build-root and --output are required'
        result=collect(args.build_root.resolve())
        args.output.write_text(json.dumps(result,indent=2)+'\n')
        print('SK-SGX EVIDENCE COLLECTED',result['totals'])


if __name__=='__main__':
    main()
