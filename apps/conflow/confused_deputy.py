#!/usr/bin/env python3
"""Direct [user_check] pointer-forgery control for the selected ConFlow ECALLs.

The original EDL declares the selected operators with [user_check] float
pointers, e.g.:

    public void ecall_encrypt([user_check]float *input,int N,
                              [user_check]float *output);

[user_check] passes the host-chosen raw pointer with no bridge copy, length,
null, canonical or range check.  This control calls the unchanged ECALLs with
`output` (and then `input`) set to an enclave-internal address taken from the
image's own writable section table:

  * BASELINE has no pointer check.  ecall_encrypt writes 20 shares into the
    enclave's own writable section; a second ecall_decrypt reads that address
    back and recovers the four input floats.  This is a direct confused-deputy
    enclave write and read, not an out-of-bounds index.
  * RADIX_ONLY/MAC27 reject the first enclave-internal store in
    encbound_require/encbound_abort before the write.

The `control` mode runs the same two ECALLs using host buffers and must pass in
all four configurations.  The functional host and the hostile-shape host are
unchanged.
"""
import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SDK = Path(os.environ.get('SGX_SDK',
    str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
CONFIGS = [('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
           ('MAC27', '0x40000000'), ('MAC27', '0x140000000')]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_dir(profile, base):
    suffix = '' if base == '0x40000000' else '-base' + base[2:]
    return ROOT / 'build/conflow' / ('SIM-' + profile +
        '-feO2-cgO2-rtO2-fused' + suffix)


def run(dest, name, command, env=None, timeout=600):
    proc = subprocess.run([str(x) for x in command], capture_output=True,
                          text=True, env=env, timeout=timeout)
    dest.mkdir(parents=True, exist_ok=True)
    log = dest / (name + '.log')
    log.write_text(proc.stdout + proc.stderr)
    return dict(command=[str(x) for x in command],
                returncode=proc.returncode, log=str(log),
                stdout=proc.stdout, stderr=proc.stderr)


def env_for(base):
    return dict(os.environ, ENCBOUND_TEST_BASE=base,
                LD_LIBRARY_PATH=str(SDK / 'sdk_libs') + ':' +
                               str(SDK / 'lib64'))


def build(dest):
    rows = []
    for profile, base in CONFIGS:
        b = build_dir(profile, base)
        b.mkdir(parents=True, exist_ok=True)
        r = run(dest, 'build-' + profile + '-' + base[2:],
                ['make', '-C', HERE, '-j4', 'PROFILE=' + profile,
                 'ENCLAVE_BASE=' + base, 'SGX_SDK=' + str(SDK),
                 'all', 'cd-host'], env=dict(os.environ), timeout=3600)
        if r['returncode']:
            raise SystemExit('build failed: ' + r['log'])
        rows.append(dict(profile=profile, base=base, build=str(b),
                         log=r['log'], log_sha256=sha(r['log'])))
    return rows


def sim(dest):
    rows = []
    for profile, base in CONFIGS:
        b = build_dir(profile, base)
        row = dict(profile=profile, base=base, modes={})
        for mode in ('control', 'cd'):
            name = profile + ('-' + base[2:] if base != '0x40000000' else '') \
                   + '-' + mode
            r = run(dest, name, [b / 'host/cd-host',
                                 b / 'enclave/enclave.signed.so', mode],
                    env=env_for(base))
            if mode == 'control':
                if r['returncode'] != 0 or '"readback":"PASS"' not in r['stdout']:
                    raise SystemExit('control failed: ' + r['log'])
            elif profile == 'BASELINE':
                if r['returncode'] != 0 or '"readback":"PASS"' not in r['stdout']:
                    raise SystemExit('baseline confused-deputy failed: ' + r['log'])
            else:
                if r['returncode'] != -4:
                    raise SystemExit('expected SIGILL, got %d: %s' %
                                     (r['returncode'], r['log']))
            row['modes'][mode] = {k: r[k] for k in
                                  ('command', 'returncode', 'log')}
            row['modes'][mode]['log_sha256'] = sha(r['log'])
        rows.append(row)
    return rows


def trace(dest):
    rows = []
    for profile, base in CONFIGS:
        if profile == 'BASELINE':
            continue
        b = build_dir(profile, base)
        script = dest / ('attr-' + profile + '-' + base[2:] + '.gdb')
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(
            'set pagination off\nset confirm off\n'
            'break conflow_cd_ready\nrun\n'
            'add-symbol-file %s -o %s\ncontinue\nbt 12\n' %
            (b / 'enclave/enclave.so', base))
        r = run(dest, 'attr-' + profile + '-' + base[2:],
                ['gdb', '-q', '-batch', '-x', script, '--args',
                 b / 'host/cd-host', b / 'enclave/enclave.signed.so', 'cd'],
                env=env_for(base))
        text = r['stdout'] + r['stderr']
        need = ['encbound_abort (code=3)', 'encbound_require',
                'ecall_encrypt',
                'prepared/Enclave.cpp:49']
        missing = [n for n in need if n not in text]
        if missing:
            raise SystemExit('attribution missing %s: %s' % (missing, r['log']))
        rows.append(dict(profile=profile, base=base,
                         abort_code=3, source_line='prepared/Enclave.cpp:49',
                         script=str(script), log=r['log'],
                         log_sha256=sha(r['log']),
                         excerpt=[l for l in text.splitlines()
                                  if any(n in l for n in need)]))
    return rows


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def write_evidence(path, results):
    record = dict(
        date=datetime.now().astimezone().date().isoformat(),
        observed_at=datetime.now(timezone.utc).isoformat(),
        application='conflow-dev/ConFlow selected operators',
        pin='fd1904271e127980c1c2a7a813a1c506266f7372',
        scope='SDK SIM direct [user_check] pointer forgery; no hardware, '
              'unbounded exploit or full-workflow claim',
        finding=dict(
            edl=['sgx_tf_ops/Enclave/Enclave.edl:36 ecall_encrypt',
                 'sgx_tf_ops/Enclave/Enclave.edl:37 ecall_decrypt'],
            sink='prepared/Enclave.cpp:49 output[i] = ... (upstream '
                 'sgx_tf_ops/Enclave/Enclave.cpp:198)',
            primitive='host-supplied [user_check] output/input pointer is '
                      'dereferenced without an outside-enclave or range check',
            baseline='writes 20 floats into an enclave-internal writable '
                    'section and reads them back through the same raw pointer',
            protected='RADIX_ONLY/MAC27 abort in encbound_require with '
                      'ENCBOUND_ERR_POLICY (code=3) before the store'),
        builds=results['builds'], sim=results['sim'],
        gdb_attribution=results['trace'],
        notes=['The target address is read from the image''s own writable '
               'section table and checked against /proc/self/maps, not a fixed '
               'scratch offset.',
               'Only BASELINE reaches the store. Protected profiles reject the '
               'raw enclave pointer before any write.',
               'This demonstrates the pointer-forgery class on an operator '
               'that already had a separate softmax out-of-bounds result.'],
        limits=['SDK SIM only; no SGX hardware.',
                'No arbitrary-address sweep, secret extraction or code '
                'execution is claimed.',
                'The enclave base is known to the host in SIM, as it is in a '
                'real SGX loader.'])
    Path(path).write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'build/conflow/confused-deputy'))
    ap.add_argument('--trace', action='store_true',
                    help='also run gdb attribution for protected profiles')
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--evidence', default=None)
    args = ap.parse_args()
    dest = Path(args.out)
    dest.mkdir(parents=True, exist_ok=True)
    builds = [] if args.skip_build else build(dest)
    if args.skip_build:
        builds = [dict(profile=p, base=b, build=str(build_dir(p, b)),
                       log='reused') for p, b in CONFIGS]
    results = dict(builds=builds, sim=sim(dest),
                   trace=trace(dest) if args.trace else [])
    results['artifacts'] = sorted(
        rel(p) for p in dest.glob('*') if p.is_file())
    record = dict(results=results, wrote_evidence=False)
    if args.evidence:
        write_evidence(Path(args.evidence), results)
        record['wrote_evidence'] = True
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
