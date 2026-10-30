#!/usr/bin/env python3
"""Supplementary release-mode USIG control: unchecked counter index.

The default USIG build maps libc++ operator[] assertions to libc assert(), so
the existing `bad-counter` control stops in __assert.  This script drives the
same unmodified source and ECALL after building only the application units with
-DNDEBUG (see build_noassert.py).  It records what the original access does
when the debug-only assertion is absent:

  BASELINE / RADIX_ONLY: heap out-of-bounds element load, then a crash on the
  unauthenticated pointer; MAC27: tagged pointer rejection at line 264.

The no-assert build is a diagnostic configuration, not part of the four-row
SDK SIM matrix.  No mechanism or frozen target changes.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
PROFILES = ('BASELINE', 'RADIX_ONLY', 'MAC27')
ROOT_BUILD = ROOT / 'build/go-consensus-usig/noassert-v1'
DEFAULT_ROOT = ROOT / 'build/go-consensus-usig/all-compat-v1'


def sha(p):
    import hashlib
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def run(name, cmd, out, env=None):
    r = subprocess.run([str(x) for x in cmd], cwd=ROOT, text=True,
                       capture_output=True, timeout=120, env=env)
    log = out / (name + '.log')
    log.write_text(r.stdout + r.stderr)
    return dict(name=name, command=[str(x) for x in cmd], returncode=r.returncode,
                log=str(log), sha256=sha(log)), log.read_text()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build-root', type=Path, default=ROOT_BUILD)
    ap.add_argument('--default-root', type=Path, default=DEFAULT_ROOT)
    ap.add_argument('--out', type=Path,
                    default=ROOT / 'build/go-consensus-usig/noassert-v1/release-control')
    ap.add_argument('--record', type=Path,
                    default=ROOT / 'build/evidence/2026-10-22-usig-release-control.json')
    ap.add_argument('--verify', action='store_true')
    a = ap.parse_args()
    if a.verify:
        r = json.loads(a.record.read_text())
        for n, h in r['inputs'].items():
            assert sha(n) == h, 'input drift ' + n
        for row in r['rows']:
            assert sha(row['host']) == row['host_sha256']
            for c in row['commands']:
                assert sha(c['log']) == c['sha256'], 'log drift ' + c['log']
        print('USIG RELEASE CONTROL VERIFY PASS', a.record)
        return
    root = a.build_root.resolve()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, LD_LIBRARY_PATH=str(SDK / 'lib64'))
    rows = []
    for name in PROFILES:
        b = root / name
        build = json.loads((b / 'build.json').read_text())
        probe = json.loads((b / 'probe.json').read_text())
        assert probe['no_assert'] is True, name + ' is not a no-assert build'
        assert build['profile'] == name
        env['ENCBOUND_TEST_BASE'] = build['base']
        commands = []
        normal, text = run(name + '-normal', [build['host'], build['signed']],
                           out, env)
        assert normal['returncode'] == 0 and 'PASS mode=normal ecalls=81' in text
        commands.append(normal)
        direct, text = run(name + '-bad-counter-direct',
                           [build['host'], build['signed'], 'bad-counter'],
                           out, env)
        commands.append(direct)
        script = out / (name + '.gdb')
        script.write_text(f'''set pagination off
set confirm off
break usig_trace_ready
run
add-symbol-file {build['signed']} -o {build['base']}
continue
bt 8
''')
        gdb, text = run(name + '-bad-counter-gdb',
                        ['gdb', '-q', '-batch', '-x', script, '--args',
                         build['host'], build['signed'], 'bad-counter'], out, env)
        commands.append(gdb)
        assert gdb['returncode'] == 0
        if name == 'BASELINE':
            assert direct['returncode'] == -11, (name, direct)
            assert 'Program received signal SIGSEGV' in text
            assert 'usig_enclave.cpp:264' in text
            meaning = ('release BASELINE: heap OOB counter element load reaches '
                       'the atomic fetch_add and the enclave crashes; no checked rejection')
        elif name == 'RADIX_ONLY':
            assert direct['returncode'] == -11, (name, direct)
            assert 'Program received signal SIGSEGV' in text
            assert '__cxx_atomic_fetch_add' in text and 'usig_enclave.cpp:264' in text
            assert 'encbound_abort' not in text
            meaning = ('release RADIX_ONLY: range alone does not stop the rounded-slot '
                       'element load; the unauthenticated pointer crashes in fetch_add')
        else:
            assert direct['returncode'] == -4, (name, direct)
            assert 'Program received signal SIGILL' in text
            assert 'encbound_abort (code=5)' in text
            assert 'encbound_require' in text and 'usig_enclave.cpp:264' in text
            meaning = ('release MAC27: tagged pointer rejection (code=5) at the '
                       'original counter access')
        # The default (assert-enabled) build/control remains a separate row.
        default_controls = a.default_root / name / 'controls.json'
        default_log = None
        if default_controls.exists():
            controls = json.loads(default_controls.read_text())
            row = next(x for x in controls['rows'] if x['case'] == 'bad-counter')
            default_log = row['debugger']['log']
            dt = Path(default_log).read_text()
            assert 'encbound_cxx_assert' in dt and '__n < size()' in dt
            assert 'encbound_abort' not in dt
        rows.append(dict(profile=name, base=build['base'], signed=build['signed'],
                         host=build['host'], host_sha256=sha(build['host']),
                         meaning=meaning, commands=commands,
                         script=str(script), script_sha256=sha(script),
                         default_assert_log=default_log))
        print(name, meaning, flush=True)
    record = dict(date='2026-10-22', mode='SDK SIM; supplementary no-assert application build',
                  matrix='BASELINE/RADIX_ONLY/MAC27; -DNDEBUG application units',
                  root=str(root), rows=rows,
                  inputs={str(p): sha(p) for p in
                          (HERE / 'release_control.py', HERE / 'host.c',
                           HERE / 'build_noassert.py', HERE / 'run.py')})
    a.record.parent.mkdir(parents=True, exist_ok=True)
    a.record.write_text(json.dumps(record, indent=2) + '\n')
    print('USIG RELEASE CONTROL PASS', a.record)


if __name__ == '__main__':
    main()
