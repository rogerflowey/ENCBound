#!/usr/bin/env python3
"""Native AddressSanitizer dig of the pinned, unmodified USIG enclave source.

The five ECALL functions are called directly.  SGX and Ed25519 services are
local stand-ins; this is not an SDK SIM or hardware result.  See README.md.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from prepare import ROOT, PINS, prepare, sha
from build import SDK

OUT = ROOT / 'build/go-consensus-usig/vuln/native'
CASES = {
    'mackey-1025': ('global-buffer-overflow', 'WRITE of size 1025',
                    'usig_enclave.cpp:129'),
    'edkey-1024': ('global-buffer-overflow', 'WRITE of size 1',
                   'usig_enclave.cpp:134'),
    'edkey-1060': ('global-buffer-overflow', 'WRITE of size 1060',
                   'usig_enclave.cpp:132'),
    'counter-oob': ('heap-buffer-overflow', 'READ of size 8',
                    'usig_enclave.cpp:264'),
}


def build(out, upstream):
    out.mkdir(parents=True, exist_ok=True)
    inc = ['-I', str(HERE / 'stubs'), '-I', str(upstream / 'trusted'),
           '-I', str(upstream / 'include'), '-I', str(SDK / 'include')]
    cflags = ['clang-21', '-std=c11', '-O1', '-g', '-fsanitize=address',
              '-fno-omit-frame-pointer', '-DNDEBUG', *inc]
    cxxflags = ['clang++-21', '-std=c++17', '-O1', '-g', '-fsanitize=address',
                '-fno-omit-frame-pointer', '-DNDEBUG', *inc]
    commands = []
    logs = out / 'build.log'
    lines = []

    def run(name, cmd):
        r = subprocess.run([str(x) for x in cmd], cwd=ROOT, text=True,
                           capture_output=True, timeout=300)
        lines.append(f'$ {" ".join(map(str, cmd))}\n{r.stdout}{r.stderr}')
        commands.append(dict(name=name, command=[str(x) for x in cmd],
                             returncode=r.returncode))
        assert r.returncode == 0, lines[-1][-4000:]
        return r

    run('harness', [*cflags, '-c', HERE / 'harness.c', '-o', out / 'harness.o'])
    run('standins', [*cxxflags, '-x', 'c++', '-c', HERE / 'stubs/sgx_glue.c',
                     '-o', out / 'sgx_glue.o'])
    run('enclave-source', [*cxxflags, '-c', upstream / 'trusted/usig_enclave.cpp',
                           '-o', out / 'usig_enclave.o'])
    run('link', ['clang++-21', '-fsanitize=address', out / 'harness.o',
                 out / 'sgx_glue.o', out / 'usig_enclave.o',
                 '-o', out / 'usig-vuln-native'])
    logs.write_text('\n'.join(lines) + '\n')
    return commands, out / 'usig-vuln-native'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, default=OUT)
    ap.add_argument('--record', type=Path,
                    default=ROOT / 'build/evidence/2026-10-22-usig-vulns.json')
    ap.add_argument('--verify', action='store_true')
    a = ap.parse_args()
    out = a.out.resolve()
    record_path = a.record
    if a.verify:
        r = json.loads(record_path.read_text())
        for n, h in r['inputs'].items():
            assert sha(n) == h, 'input drift ' + n
        for c in r['commands']:
            assert c['returncode'] == 0
        for c in r['cases']:
            assert sha(c['log']) == c['sha256'], 'log drift ' + c['log']
            text = Path(c['log']).read_text()
            for marker in c['markers']:
                assert marker in text, (c['case'], marker)
        print('USIG VULN DIG VERIFY PASS', record_path)
        return
    upstream = prepare()
    commands, binary = build(out, upstream)
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0')
    cases = []
    for name, markers in CASES.items():
        r = subprocess.run([str(binary), name], cwd=ROOT, text=True,
                           capture_output=True, timeout=120, env=env)
        log = out / (name + '.log')
        log.write_text(r.stdout + r.stderr)
        text = log.read_text()
        assert r.returncode != 0, (name, text[-4000:])
        for marker in markers:
            assert marker in text, (name, marker, text[-4000:])
        cases.append(dict(case=name, expected='native ASan: ' + ', '.join(markers),
                          returncode=r.returncode, log=str(log), sha256=sha(log),
                          markers=list(markers)))
        print(name, 'ASAN', r.returncode, flush=True)
    control = subprocess.run([str(binary), 'counter-in-range'], cwd=ROOT,
                             text=True, capture_output=True, timeout=120, env=env)
    (out / 'counter-in-range.log').write_text(control.stdout + control.stderr)
    assert control.returncode == 0 and 'COUNTER-IN-RANGE PASS' in control.stdout
    record = dict(date='2026-10-22', mode='native ASan; SGX and Ed25519 stand-ins',
                  target=dict(repository=PINS['repository'],
                              revision=PINS['revision'],
                              archive_sha256=PINS['archive_sha256']),
                  source=str(upstream), binary=str(binary),
                  commands=commands, cases=cases,
                  control=dict(returncode=control.returncode,
                               log=str(out / 'counter-in-range.log'),
                               sha256=sha(out / 'counter-in-range.log')),
                  inputs={str(p): sha(p) for p in
                          (HERE / 'run.py', HERE / 'harness.c',
                           HERE / 'stubs/usig_enclave_t.h',
                           HERE / 'stubs/sgx_glue.c',
                           HERE.parent / 'pins.json')})
    record_path.write_text(json.dumps(record, indent=2) + '\n')
    print('USIG VULN DIG PASS', record_path)


if __name__ == '__main__':
    main()
