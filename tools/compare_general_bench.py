#!/usr/bin/env python3
"""Interleave the three trusted-runtime experiments on retained SIM images."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'apps/general-bench'))
from run import Session, percentile, PROFILES
from reference import NAMES

VARIANTS = ['o0', 'o2', 'optimized']


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main(a):
    variants = ['siphash24','aes128_cmac'] if a.study == 'mac' else ['off','inline','loops'] if a.study == 'fast' else ['off', 'loop', 'proofs'] if a.study == 'proofs' else (['off', 'block', 'loop'] if a.study == 'reuse' else VARIANTS)
    a.out.mkdir(parents=True, exist_ok=False)
    builds = {}
    inputs = {}
    shared = None
    sources = None
    references = None
    memory = None
    for variant in variants:
        run = a.runs_root / variant
        if (run / 'FAILED.txt').exists():
            raise RuntimeError('failed input run: ' + str(run))
        manifest = json.loads((run / 'manifest.json').read_text())
        for name, expected in manifest.items():
            if digest(run / name) != expected:
                raise RuntimeError('input artifact changed: ' + str(run / name))
        inputs[variant] = dict(path=str(run), manifest_sha256=digest(run / 'manifest.json'))
        refs = {p.name: digest(p) for p in (run / 'references').glob('*.bin')}
        if references is not None and references != refs:
            raise RuntimeError('references differ')
        references = refs
        for profile in PROFILES:
            artifact = run / 'artifacts' / profile
            inv = json.loads((artifact / 'inventory.json').read_text())
            if shared is not None and shared != inv['shared_inputs']:
                raise RuntimeError('shared source snapshots differ')
            if sources is not None and sources != inv['sources']:
                raise RuntimeError('benchmark source snapshots differ')
            shared, sources = inv['shared_inputs'], inv['sources']
            expected_opt = '-O0' if variant == 'o0' else '-O2'
            expected_core = 'fused' if variant == 'optimized' or a.study in ['reuse','proofs','fast','mac'] else 'separate'
            if a.study == 'mac':
                assert inv['mac_algorithm']==variant and inv['check_reuse']=='loop'
                assert inv['fast_paths']=='loops' and inv['local_proofs']==0
            if a.study == 'fast':
                assert inv['check_reuse'] == 'loop' and inv['local_proofs'] == 0
                assert inv['fast_paths'] == variant
            if a.study == 'reuse': assert inv['check_reuse'] == variant
            if a.study == 'proofs':
                assert inv['check_reuse'] == ('loop' if variant == 'proofs' else variant)
                assert inv['local_proofs'] == int(variant == 'proofs')
            assert inv['trusted_flags'].startswith(expected_opt + ' ')
            assert inv['trusted_core'] == expected_core
            if profile != 'BASELINE':
                diag = json.loads((run / 'diagnostics' / (profile + '.json')).read_text())
                assert len(diag['security']) == 3 and all(r['status'] == 'passed' for r in diag['security'])
                if a.study in ['reuse','proofs'] and variant != 'off':
                    assert len(diag['prepared_security']) == 3 and all(r['status'] == 'passed' for r in diag['prepared_security'])
                assert len(diag['memory']) == 5 and all(not any(r['final'].values()) for r in diag['memory'])
                geometry = [{k:v for k,v in row.items() if k != 'profile'} for row in diag['memory']]
                if memory is not None and memory != geometry:
                    raise RuntimeError('protected allocation geometry/counts differ')
                memory = geometry
            # Session's normal build layout, pointing at immutable retained files.
            build = a.out / 'images' / variant / profile
            (build / 'host').mkdir(parents=True)
            (build / 'host/host').symlink_to(artifact / 'host')
            (build / 'enclave').symlink_to(artifact, target_is_directory=True)
            builds[(variant, profile)] = build
    context = dict(mode='SDK SIM', inputs=inputs, cpu=a.cpu, load_start=os.getloadavg(),
                   start_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                   warmups=5, batches=30, ordering=f'rotate all {len(builds)} variant/profile rows',
                   host_flags='-O0 -g', frontend='-O2', codegen='-O2',
                   note='Identical repeat count across all selected rows per workload; no profiler attached.')
    (a.out / 'context.json').write_text(json.dumps(context, indent=2)+'\n')
    samples = []
    summary = []
    lifetimes = []
    keys = list(builds)
    with (a.out / 'samples.csv').open('w') as f:
        writer = csv.DictWriter(f, fieldnames=['case','variant','profile','batch','order','iterations','ns','ns_per_iteration'])
        writer.writeheader()
        for case, name in enumerate(NAMES):
            sessions = {}
            try:
                for key in keys:
                    variant, profile = key
                    ref = a.runs_root / variant / 'references' / (name+'.bin')
                    sessions[key] = Session(builds[key], case, ref, a.cpu, a.sdk,
                                             a.out / (name+'-'+variant+'-'+profile+'.jsonl'))
                pilots = {}
                for key, s in sessions.items():
                    first = s.sample(1, case)
                    pilots[key] = statistics.median(s.sample(3, case)['ns']/3 for _ in range(3))
                    lifetimes.append(dict(case=name,variant=key[0],profile=key[1],**s.ready,first_ns=first['ns']))
                n = max(1,min(100000,math.ceil(1e6/min(pilots.values())),math.floor(2e8/max(pilots.values()))))
                for _ in range(5):
                    for key in keys: sessions[key].sample(n,case)
                for batch in range(30):
                    order = keys[batch % len(keys):] + keys[:batch % len(keys)]
                    for position, key in enumerate(order):
                        row = sessions[key].sample(n,case)
                        rec = dict(case=name,variant=key[0],profile=key[1],batch=batch,
                                   order=position,iterations=n,ns=row['ns'],ns_per_iteration=row['ns']/n)
                        samples.append(rec); writer.writerow(rec); f.flush()
                record = dict(case=name,iterations=n,variants={})
                for variant in variants:
                    metrics = {}
                    for profile in PROFILES:
                        v = [r['ns_per_iteration'] for r in samples if (r['case'],r['variant'],r['profile']) == (name,variant,profile)]
                        metrics[profile] = dict(median_ns=statistics.median(v),p10_ns=percentile(v,.1),p90_ns=percentile(v,.9))
                    med = {p:metrics[p]['median_ns'] for p in PROFILES}
                    record['variants'][variant] = dict(profiles=metrics,mac_vs_baseline=med['MAC27']/med['BASELINE'],
                        radix_vs_baseline=med['RADIX_ONLY']/med['BASELINE'],mac_vs_radix=med['MAC27']/med['RADIX_ONLY'])
                summary.append(record)
                print(name, {v:round(record['variants'][v]['mac_vs_baseline'],2) for v in variants},flush=True)
                for key,s in sessions.items():
                    lifetimes.append(dict(case=name,variant=key[0],profile=key[1],**s.close()))
            finally:
                for s in sessions.values(): s.abort()
    means = {v:{k:statistics.geometric_mean(r['variants'][v][k] for r in summary)
                for k in ['mac_vs_baseline','radix_vs_baseline','mac_vs_radix']} for v in variants}
    for name,data in [('summary',summary),('geomean',means),('lifetimes',lifetimes)]:
        (a.out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
    context.update(load_end=os.getloadavg(),end_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
    for variant in variants:
        run = a.runs_root / variant
        for name, expected in json.loads((run / 'manifest.json').read_text()).items():
            if digest(run / name) != expected:
                raise RuntimeError('input artifact changed during comparison')
    (a.out/'context.json').write_text(json.dumps(context,indent=2)+'\n')
    shutil.copy2(__file__,a.out/'compare_general_bench.py')
    # Exclude symlinked input images: their complete manifests are verified above.
    (a.out/'manifest.json').write_text(json.dumps({str(p.relative_to(a.out)):digest(p)
        for p in a.out.iterdir() if p.is_file()},indent=2)+'\n')
    print(json.dumps(means,indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--study', choices=['runtime', 'reuse', 'proofs', 'fast', 'mac'], default='runtime')
    p.add_argument('--runs-root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--cpu',type=int,default=min(os.sched_getaffinity(0)))
    p.add_argument('--sdk',type=Path,default=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[1] / 'deps/sgxsdk')))))
    a = p.parse_args(); a.runs_root = a.runs_root.resolve(); a.out = a.out.resolve()
    main(a)
