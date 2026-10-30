#!/usr/bin/env python3
"""Software-PC sampling of retained SDK SIM benchmark images, outside timing.

The SDK's anonymous mapping has no perf symbols. Resolve sampled PCs against
the retained unsigned ELF at its verified 0x40000000 load base. Do not use
these sampled executions as benchmark timing, dynamic check counts or hardware
cycle attribution.
"""
import argparse
import bisect
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess

NAMES = ['lists', 'heapsort', 'atax', 'gemm', 'jacobi']


def main(a):
    a.out.mkdir(parents=True, exist_ok=False)
    artifacts = a.run / 'artifacts' / a.profile
    summary = next(r for r in json.loads((a.run / 'summary.json').read_text())
                   if r['case'] == a.case)
    ns = summary['profiles'][a.profile]['median_ns']
    repeats = min(100000, max(1, round(2e9 / ns)))
    reference = a.run / 'references' / (a.case + '.bin')
    command = ['perf', 'record', '-o', str(a.out / 'perf.data'),
               '-e', 'cpu-clock:u', '-F', '499', '--', 'taskset', '-c', str(a.cpu),
               str(artifacts / 'host'), str(NAMES.index(a.case)), str(reference)]
    env = dict(os.environ, LD_LIBRARY_PATH=str(a.sdk / 'lib64'))
    p = subprocess.run(command, cwd=artifacts, env=env, text=True,
                       input=f'1\n{repeats}\n{repeats}\n{repeats}\n0\n',
                       capture_output=True, timeout=120)
    (a.out / 'host.log').write_text(p.stdout)
    (a.out / 'perf.log').write_text(p.stderr)
    if p.returncode or p.stdout.count('"correct":true') != 4:
        raise RuntimeError('profile execution failed')
    script = subprocess.run(['perf', 'script', '-i', str(a.out / 'perf.data'),
                             '-F', 'ip'], text=True, capture_output=True, check=True)
    (a.out / 'ips.txt').write_text(script.stdout)
    (a.out / 'script.log').write_text(script.stderr)
    nm = subprocess.check_output(['nm', '-n', '-S', '--defined-only',
                                  str(artifacts / 'enclave.so')], text=True)
    (a.out / 'symbols.txt').write_text(nm)
    symbols = []
    for line in nm.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in {'t', 'T'}:
            symbols.append((int(fields[0], 16), int(fields[1], 16), fields[3]))
    symbols.sort()
    starts = [r[0] for r in symbols]
    counts = Counter()
    for line in script.stdout.splitlines():
        ip = int(line.strip(), 16) - 0x40000000
        i = bisect.bisect_right(starts, ip) - 1
        if i >= 0 and symbols[i][0] <= ip < symbols[i][0] + symbols[i][1]:
            counts[symbols[i][2]] += 1
        elif 0 <= ip < 0x4000000:
            counts['[unresolved enclave]'] += 1
        else:
            counts['[outside enclave]'] += 1
    total = sum(counts.values())
    if total < 100:
        raise RuntimeError('too few CPU samples')
    inputs = [artifacts / n for n in ['host', 'enclave.so', 'enclave.signed.so']]
    inputs += [reference, Path(__file__).resolve()]
    result = dict(profile=a.profile, case=a.case, mode='SDK SIM',
                  event='cpu-clock:u', frequency=499, samples=total, command=command,
                  repeats=repeats, cpu=a.cpu,
                  inputs={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
                  functions=[dict(name=n, samples=c, percent=100*c/total)
                             for n, c in counts.most_common()],
                  limitations='Statistical PC samples including startup; not cycles, call counts or timing results.')
    (a.out / 'profile.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['functions'][:12], indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--profile', choices=['BASELINE', 'RADIX_ONLY', 'MAC27'], default='MAC27')
    p.add_argument('--case', choices=NAMES, default='gemm')
    p.add_argument('--cpu', type=int, default=min(os.sched_getaffinity(0)))
    p.add_argument('--sdk', type=Path, default=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[1] / 'deps/sgxsdk')))))
    a = p.parse_args()
    a.run = a.run.resolve()
    a.out = a.out.resolve()
    main(a)
