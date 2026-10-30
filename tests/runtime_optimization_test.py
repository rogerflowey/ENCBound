#!/usr/bin/env python3
"""Native regression matrix for trusted optimization; no SGX timing claims."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main(out):
    out.mkdir(parents=True, exist_ok=False)
    results = []
    transcripts = {}
    for opt, core in [('-O0', 'separate'), ('-O2', 'separate'), ('-O2', 'fused')]:
        label = opt[1:] + '-' + core
        build = out / label
        build.mkdir()
        rt = ['check_core'] if core == 'fused' else ['siphash', 'runtime', 'capability']
        rt += ['allocations', 'allocator', 'adapters']
        sources = [str(ROOT / 'runtime' / (n + '.c')) for n in rt]
        flags = [opt, '-g', '-Wall', '-Wextra', '-Wno-unused-parameter',
                 '-fstack-protector-strong', '-MMD', '-MP']
        flags += ['-I' + str(ROOT / n) for n in ['include', 'runtime', 'wrappers', 'tests']]
        # Existing independent native expectations, including sparse allocator
        # failures/coalescence, stack clearing, adapters and session behavior.
        command = ['make', '-C', str(ROOT / 'tests'), '-j4', 'all',
                   'BUILD=' + str(build), 'CC=cc', 'CFLAGS=' + ' '.join(flags),
                   'RT_SRC=' + ' '.join(sources)]
        with (build / 'build.log').open('w') as f:
            f.write(json.dumps(command) + '\n'); f.flush()
            subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, check=True)
        for profile in ['radix', 'mac27']:
            for suite in ['runtime', 'allocator', 'adapters', 'sdk_adapters', 'session']:
                exe = build / (suite + '_test_' + profile)
                p = subprocess.run([str(exe)], text=True, capture_output=True, check=True)
                (build / (exe.name + '.log')).write_text(p.stdout + p.stderr)
                results.append(dict(configuration=label, profile=profile, suite=suite, status='passed'))
            exe = build / ('equivalence_' + profile)
            command = ['cc', *flags, *(['-DENCBOUND_MAC27'] if profile == 'mac27' else []),
                       *sources, str(ROOT / 'tests/fake_platform.c'),
                       str(ROOT / 'tests/runtime_optimization_equivalence.c'), '-o', str(exe)]
            subprocess.run(command, check=True)
            p = subprocess.run([str(exe)], text=True, capture_output=True, check=True)
            (build / (exe.name + '.log')).write_text(p.stdout + p.stderr)
            if profile in transcripts:
                assert transcripts[profile] == p.stdout, 'optimization changed corpus outcomes'
            transcripts[profile] = p.stdout
            results.append(dict(configuration=label, profile=profile, suite='equivalence',
                                transcript=p.stdout.strip(), status='passed'))
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print('RUNTIME OPTIMIZATION PASS', len(results), 'groups')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    main(p.parse_args().out.resolve())
