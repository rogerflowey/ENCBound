#!/usr/bin/env python3
"""USIG init-overflow consequence control on the existing four SDK SIM rows.

A MAC key length that reaches edd25519_sk replaces the Ed25519 signing key in
BASELINE.  The host then verifies the fresh signature with the attacker public
key and checks that the legitimate key fails.  Protected profiles terminate at
the checked strncpy with ENCBOUND_ERR_RANGE (code 4).  No enclave rebuild.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
CONFIGS = (('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
           ('MAC27', '0x40000000'), ('MAC27-high', '0x140000000'))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def symbol_addresses(signed):
    text = subprocess.check_output(['nm', '-an', '--defined-only', str(signed)],
                                   text=True)
    wanted = {'_ZL12usig_mac_key', '_ZL11edd25519_sk'}
    found = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in wanted:
            found[parts[2]] = int(parts[0], 16)
    assert set(found) == wanted
    return found


def run(name, cmd, out, env):
    r = subprocess.run([str(x) for x in cmd], cwd=ROOT, text=True,
                       capture_output=True, timeout=120, env=env)
    log = out / (name + '.log')
    log.write_text(r.stdout + r.stderr)
    return dict(name=name, command=[str(x) for x in cmd], returncode=r.returncode,
                log=str(log), sha256=sha(log)), log.read_text()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build-root', type=Path,
                    default=ROOT / 'build/go-consensus-usig/all-compat-v1')
    ap.add_argument('--out', type=Path,
                    default=ROOT / 'build/go-consensus-usig/key-replace')
    ap.add_argument('--record', type=Path,
                    default=ROOT / 'build/evidence/2026-10-22-usig-key-replace.json')
    ap.add_argument('--verify', action='store_true')
    a = ap.parse_args()
    if a.verify:
        r = json.loads(a.record.read_text())
        for n, h in r['inputs'].items():
            assert sha(n) == h, 'input drift ' + n
        for row in r['rows']:
            assert sha(row['host']) == row['host_sha256']
            assert sha(row['signed']) == row['signed_sha256']
            for c in row['commands']:
                assert sha(c['log']) == c['sha256'], 'log drift ' + c['log']
        print('USIG KEY REPLACE VERIFY PASS', a.record)
        return
    root = a.build_root.resolve()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, LD_LIBRARY_PATH=str(SDK / 'lib64'))
    rows = []
    for name, base in CONFIGS:
        b = root / name
        build = json.loads((b / 'build.json').read_text())
        assert build['profile'].split('-')[0] in name or name == 'BASELINE'
        signed = Path(build['signed'])
        sym = symbol_addresses(signed)
        off = sym['_ZL11edd25519_sk'] - sym['_ZL12usig_mac_key']
        assert off >= 1024
        host = out / ('key-replace-' + name)
        commands = []
        cc = ['cc', '-O2', '-g', '-Wno-deprecated-declarations',
              '-I', b / 'generated', '-I', SDK / 'include',
              HERE / 'key_replace_host.c', b / 'generated/usig_enclave_u.c',
              '-L', SDK / 'lib64', '-Wl,-rpath-link,' + str(SDK / 'lib64'),
              '-lsgx_urts_sim', '-lpthread', '-lcrypto', '-o', host]
        c, _ = run(name + '-compile', cc, out, env)
        assert c['returncode'] == 0
        commands.append(c)
        env['ENCBOUND_TEST_BASE'] = base
        direct, text = run(name + '-direct', [host, signed, off], out, env)
        commands.append(direct)
        if name == 'BASELINE':
            assert direct['returncode'] == 0, (name, text[-3000:])
            assert 'KEY-REPLACE PASS offset=%u' % off in text
            meaning = ('BASELINE: overflow replaces edd25519_sk; signature verifies '
                       'with the attacker key and not the legitimate key')
        else:
            assert direct['returncode'] == -4, (name, direct, text[-3000:])
            script = out / (name + '.gdb')
            script.write_text(f'''set pagination off
set confirm off
break usig_trace_ready
run
add-symbol-file {signed} -o {base}
continue
bt 10
''')
            gdb, gtext = run(name + '-gdb',
                             ['gdb', '-q', '-batch', '-x', script, '--args',
                              host, signed, off], out, env)
            commands.append(gdb)
            assert gdb['returncode'] == 0
            assert 'Program received signal SIGILL' in gtext
            assert 'encbound_abort (code=4)' in gtext
            assert 'encbound_strncpy' in gtext
            assert 'n=%u' % (off + 64) in gtext
            assert 'usig_enclave.cpp:129' in gtext
            meaning = ('%s: checked strncpy RANGE (code=4) at the original call, '
                       'before the overflow reaches edd25519_sk' % name)
        rows.append(dict(configuration=name, profile=build['profile'], base=base,
                         off=off, length=off + 64, signed=str(signed),
                         signed_sha256=sha(signed), host=str(host),
                         host_sha256=sha(host), meaning=meaning, commands=commands))
        print(name, 'off=%u length=%u' % (off, off + 64), meaning, flush=True)
    record = dict(date='2026-10-22', mode='SDK SIM; existing four USIG images',
                  root=str(root), rows=rows,
                  inputs={str(p): sha(p) for p in
                          (HERE / 'key_replace.py', HERE / 'key_replace_host.c',
                           HERE / 'host.c', HERE / 'build.py')})
    a.record.parent.mkdir(parents=True, exist_ok=True)
    a.record.write_text(json.dumps(record, indent=2) + '\n')
    print('USIG KEY REPLACE PASS', a.record)


if __name__ == '__main__':
    main()
