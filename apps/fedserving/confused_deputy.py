#!/usr/bin/env python3
"""Baseline-vs-protected FedServing [user_check] confused-deputy demonstration.

Uses the existing signed SDK SIM images (run apps/fedserving/run.py first).
BASELINE is stock Intel: the host-chosen input/output pointer is used with no
check, so pointing it inside the enclave makes the enclave read/write its own
memory.  RADIX_ONLY/MAC27 insert encbound_require and must trap before the
first enclave-internal access.

This is an out-of-tree probe over the unchanged public ECALL.  It does not
modify the application, EDL or bridge.
"""
import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
DEFAULT_OUT = ROOT/'build/first10-2026-10-21/fedserving'
CONFIGS = [('BASELINE', 0x40000000), ('RADIX_ONLY', 0x40000000),
           ('MAC27', 0x40000000), ('MAC27-high', 0x140000000)]


def make_preds(seed):
    return [[[1.0 + i + 0.01*j + 0.001*k + 0.05*seed for k in range(10)]
             for j in range(16)] for i in range(6)]


def reference(preds):
    """The published L2 equations, including the upstream denominator and
    output-before-final-update ordering."""
    weights = [1.0]*6
    out = None
    for _ in range(20):
        denominator = sum([weights[0]]*6)
        out = [[sum(weights[i]*preds[i][j][k] for i in range(6))/denominator
                for k in range(10)] for j in range(16)]
        losses = [sum(math.sqrt(sum((preds[i][j][k]-out[j][k])**2
                                    for k in range(10))) for j in range(16))
                  for i in range(6)]
        total = sum(losses)
        nw = [weights[i] if total == 0 or losses[i] == 0 else
              -math.log(losses[i]/total) for i in range(6)]
        denominator = sum(math.exp(w) for w in nw)
        weights = [math.exp(w)/denominator for w in nw]
    return [x for row in out for x in row]


def max_diff(a, b):
    if len(a) != len(b):
        raise ValueError('length mismatch')
    worst = 0.0
    for x, y in zip(a, b):
        worst = max(worst, abs(x-y))
    return worst


def matches(a, b):
    return (len(a) == len(b) and
            all(math.isclose(x, y, rel_tol=1e-9, abs_tol=1e-11)
                for x, y in zip(a, b)))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_probe(out):
    probe = out/'confused-deputy-probe'
    gen = out/'MAC27'/'generated'
    prepared = out/'MAC27'/'prepared'
    cmd = ['cc', '-m64', '-O2', '-g', '-Wall', '-Wextra',
           '-I'+str(prepared), '-I'+str(gen), '-I'+str(SDK/'include'),
           str(HERE/'confused_deputy.c'), str(gen/'Enclave_u.c'),
           '-o', str(probe),
           '-L'+str(SDK/'lib64'), '-Wl,-rpath-link,'+str(SDK/'lib64'),
           '-L'+str(SDK/'sdk_libs'), '-lsgx_urts_sim', '-lpthread']
    subprocess.run(cmd, check=True)
    return probe, cmd


def run(probe, image, base, mode, result_path):
    env = dict(os.environ, LD_LIBRARY_PATH=f'{SDK}/sdk_libs:{SDK}/lib64')
    cmd = [str(probe), str(image), hex(base), mode, str(result_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env,
                          timeout=180)
    return dict(command=list(map(str, cmd)), returncode=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr)


def trapped(rc, stderr):
    """The protected images abort with __builtin_trap (SIGILL) at the first
    enclave-internal access, before the second 'Results combined!' message."""
    return ((rc in (-4, 132) or rc != 0) and
            'Combining results inside enclave...' in stderr and
            'Results combined!' not in stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=DEFAULT_OUT)
    a = p.parse_args()
    out = a.out.resolve()
    if not (out/'MAC27'/'enclave'/'enclave.signed.so').exists():
        sys.exit('build the four images first: tools/with-integration-defaults.sh '
                 'python3 apps/fedserving/run.py')
    out.mkdir(parents=True, exist_ok=True)
    probe, build_cmd = build_probe(out)

    rows = []
    for name, base in CONFIGS:
        image = out/name/'enclave'/'enclave.signed.so'
        if not image.exists():
            continue
        write_path = out/f'confused-deputy-{name}-write.json'
        read_path = out/f'confused-deputy-{name}-read.json'
        w = run(probe, image, base, 'write', write_path)
        r = run(probe, image, base, 'read', read_path)
        row = dict(configuration=name, base=hex(base), image=str(image),
                   image_sha256=sha(image), write=w, read=r)
        if name == 'BASELINE':
            wd = json.loads(write_path.read_text())
            expected_w = reference(make_preds(0))
            row['write']['oracle_max_abs_diff'] = max_diff(wd['write_back'], expected_w)
            row['write']['pass'] = (w['returncode'] == 0 and
                                    'status=0 ret=0' in w['stdout'] and
                                    matches(wd['write_back'], expected_w))
            rd = json.loads(read_path.read_text())
            markers = [reference(make_preds(s)) for s in range(6)]
            read_preds = [[[markers[i][j*10+k] for k in range(10)]
                           for j in range(16)] for i in range(6)]
            expected_r = reference(read_preds)
            row['read']['oracle_max_abs_diff'] = max_diff(rd['read_output'], expected_r)
            row['read']['pass'] = (r['returncode'] == 0 and
                                   'status=0 ret=0' in r['stdout'] and
                                   matches(rd['read_output'], expected_r))
        else:
            row['write']['blocked'] = trapped(w['returncode'], w['stderr'])
            row['read']['blocked'] = trapped(r['returncode'], r['stderr'])
        rows.append(row)

    result = dict(app='fedserving', mode='SDK SIM',
                  probe=str(probe), probe_sha256=sha(probe),
                  build_command=build_cmd, rows=rows,
                  claim='BASELINE accepts host-chosen [user_check] pointers that '
                        'point inside the enclave and reads/writes enclave memory; '
                        'RADIX_ONLY/MAC27 trap before the same access.',
                  limits='SDK SIM only; WORKSPACE 0x3d000 is BASELINE heap / '
                         'protected .globalbss scratch. Write is a constrained '
                         '160-double write. Read returns a function of the target '
                         'region; full secret extraction is not claimed.')
    (out/'confused-deputy.json').write_text(json.dumps(result, indent=2)+'\n')

    print(f"{'config':<12} {'write':<34} {'read':<34}")
    for row in rows:
        def cell(side):
            if 'pass' in side:
                return ('UNCHECKED: ECALL ok, oracle diff %.1e' %
                        side['oracle_max_abs_diff']) if side['pass'] else 'FAIL'
            return 'BLOCKED (SIGILL/trap)' if side.get('blocked') else 'NOT BLOCKED'
        print(f"{row['configuration']:<12} {cell(row['write']):<34} {cell(row['read']):<34}")
    print('record:', out/'confused-deputy.json')


if __name__ == '__main__':
    main()
