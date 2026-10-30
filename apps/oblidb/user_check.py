#!/usr/bin/env python3
"""Direct [user_check] pointer-forgery control for ObliDB opOneLinearScanBlock.

The unchanged EDL declares:

    public int opOneLinearScanBlock(int structureId, int index,
                                    [user_check]Linear_Scan_Block* block,
                                    int write);

[user_check] passes the host-chosen raw pointer with no bridge copy, length,
null, canonical or outside-enclave check.  The unchanged body reads 512 bytes
from `block` unconditionally (prepared/enclave_data_structures.cpp:88) and
writes 512 bytes back on a read (prepared/enclave_data_structures.cpp:111).

The `cd` mode names the image's own `linOramCache` global as the block:

  * store a known pattern in block 0 through a host buffer;
  * read block 0 into the raw enclave address (enclave write to target);
  * write that raw address into block 1 (enclave read from target);
  * read block 1 back through a host buffer.

BASELINE must recover the pattern.  RADIX_ONLY/MAC27 must reject the first raw
enclave access in encbound_require/encbound_abort before the 512-byte copy.

The `control` mode uses only host buffers and must pass in every profile.
The functional host is unchanged.
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
SDK = Path(os.environ.get(
    'SGX_SDK',
    str(ROOT/'deps/sgxsdk')))
BASE = '0x40000000'
HIGH_BASE = '0x140000000'
CONFIGS = [('BASELINE', BASE), ('RADIX_ONLY', BASE), ('MAC27', BASE)]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def build_dir(profile, base):
    suffix = '' if base == BASE else '-base' + base[2:]
    return ROOT / 'build/oblidb/all-compat-v1' / (profile + suffix)


def run(dest, name, command, env=None, timeout=3600):
    proc = subprocess.run([str(x) for x in command], capture_output=True,
                          text=True, env=env, timeout=timeout)
    dest.mkdir(parents=True, exist_ok=True)
    log = dest / (name + '.log')
    log.write_text(proc.stdout + proc.stderr)
    return dict(command=[str(x) for x in command],
                returncode=proc.returncode, log=rel(log),
                log_sha256=sha(log),
                stdout=proc.stdout, stderr=proc.stderr)


def env_for(base):
    return dict(os.environ, ENCBOUND_TEST_BASE=base,
                LD_LIBRARY_PATH=str(SDK / 'lib64') + ':' +
                               str(SDK / 'sdk_libs'))


def build(configs, dest):
    rows = []
    for profile, base in configs:
        b = build_dir(profile, base)
        b.mkdir(parents=True, exist_ok=True)
        r = run(dest, 'build-' + profile + '-' + base[2:],
                ['make', '-C', HERE, '-j4', 'BUILD=' + str(b),
                 'PROFILE=' + profile, 'ENCLAVE_BASE=' + base,
                 'SGX_SDK=' + str(SDK), 'all', 'uc-host'],
                env=dict(os.environ))
        if r['returncode']:
            raise SystemExit('build failed: ' + r['log'])
        rows.append(dict(profile=profile, base=base, build=rel(b),
                         log=r['log'], log_sha256=r['log_sha256']))
    return rows


def sim(configs, dest):
    rows = []
    for profile, base in configs:
        b = build_dir(profile, base)
        row = dict(profile=profile, base=base, modes={})
        # The functional host is a regression row, not part of the forgery claim.
        name = profile + '-' + base[2:] + '-functional'
        r = run(dest, name,
                [b / 'host/host', b / 'enclave/enclave.signed.so'],
                env=env_for(base))
        if r['returncode'] or '"result":"PASS"' not in r['stdout']:
            raise SystemExit('functional host failed: ' + r['log'])
        row['modes']['functional'] = {k: r[k] for k in
                                      ('command', 'returncode', 'log',
                                       'log_sha256')}
        for mode in ('control', 'cd'):
            name = profile + '-' + base[2:] + '-' + mode
            r = run(dest, name,
                    [b / 'host/uc-host', b / 'enclave/enclave.signed.so',
                     mode], env=env_for(base))
            if mode == 'control':
                if r['returncode'] or '"readback":"PASS"' not in r['stdout']:
                    raise SystemExit('control failed: ' + r['log'])
            elif profile == 'BASELINE':
                if r['returncode'] or '"readback":"PASS"' not in r['stdout']:
                    raise SystemExit('baseline confused-deputy failed: ' +
                                     r['log'])
            else:
                if r['returncode'] != -4:
                    raise SystemExit('expected SIGILL, got %d: %s' %
                                     (r['returncode'], r['log']))
            row['modes'][mode] = {k: r[k] for k in
                                  ('command', 'returncode', 'log',
                                   'log_sha256')}
        rows.append(row)
    return rows


def trace(configs, dest):
    rows = []
    for profile, base in configs:
        if profile == 'BASELINE':
            continue
        b = build_dir(profile, base)
        script = dest / ('attr-' + profile + '-' + base[2:] + '.gdb')
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(
            'set pagination off\nset confirm off\n'
            'handle SIGILL stop print\n'
            'break oblidb_uc_ready\nrun\n'
            'add-symbol-file %s -o %s\ncontinue\nbt 12\n' %
            (b / 'enclave/enclave.so', base))
        r = run(dest, 'attr-' + profile + '-' + base[2:],
                ['gdb', '-q', '-batch', '-x', script, '--args',
                 b / 'host/uc-host', b / 'enclave/enclave.signed.so', 'cd'],
                env=env_for(base))
        text = r['stdout'] + r['stderr']
        need = ['encbound_abort (code=3)', 'encbound_require',
                'encbound_memcpy', 'opOneLinearScanBlock',
                'prepared/enclave_data_structures.cpp:88']
        missing = [n for n in need if n not in text]
        if missing:
            raise SystemExit('attribution missing %s: %s' %
                             (missing, r['log']))
        rows.append(dict(profile=profile, base=base,
                         abort_code=3,
                         source_line='prepared/enclave_data_structures.cpp:88',
                         script=rel(script), log=r['log'],
                         log_sha256=r['log_sha256'],
                         excerpt=[l for l in text.splitlines()
                                  if any(n in l for n in need)]))
    return rows


def write_evidence(path, results):
    record = dict(
        date=datetime.now().astimezone().date().isoformat(),
        observed_at=datetime.now(timezone.utc).isoformat(),
        application='SabaEskandarian/ObliDB selected linear-scan block workload',
        pin='6de5ba15eb27b4ddc86481e2eb8db549159344ea',
        scope='SDK SIM direct [user_check] pointer forgery; no hardware, '
              'unbounded exploit, full SQL/ORAM or full-workflow claim',
        finding=dict(
            edl='isv_enclave/isv_enclave.edl:109 opOneLinearScanBlock',
            sink=['prepared/enclave_data_structures.cpp:88 '
                  'memcpy(real->data, block, BLOCK_DATA_SIZE)',
                  'prepared/enclave_data_structures.cpp:111 '
                  'if(!write) memcpy(block, real->data, BLOCK_DATA_SIZE)'],
            primitive='host-supplied [user_check] block pointer is '
                      'dereferenced without an outside-enclave or range check; '
                      'the body first reads 512 bytes from it and, on a read, '
                      'writes 512 bytes back',
            baseline='writes block 0 into the enclave-internal linOramCache '
                     'and reads the same address back through block 1',
            protected='RADIX_ONLY/MAC27 abort in encbound_require with '
                      'ENCBOUND_ERR_POLICY (code=3) before the first '
                      '512-byte access'),
        builds=results['builds'], sim=results['sim'],
        gdb_attribution=results['trace'],
        notes=['The target is the image''s own LOCAL symbol linOramCache, '
               'found in .symtab and checked against /proc/self/maps.',
               'Only BASELINE reaches a copy. Protected profiles reject the '
               'raw enclave pointer before any read or write.',
               'The target is not otherwise used by the selected linear path '
               '(MIXED_USE_MODE=0), so the BASELINE read-back is attributable '
               'to the two opOneLinearScanBlock calls.'],
        limits=['SDK SIM only; no SGX hardware.',
                'No arbitrary-address sweep, secret extraction or code '
                'execution is claimed.',
                'The host knows the enclave base and the image symbol in SIM, '
                'as a loader does; this is not a production address leak.'])
    Path(path).write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'build/oblidb/user-check'))
    ap.add_argument('--trace', action='store_true',
                    help='also run gdb attribution for protected profiles')
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--high-base', action='store_true',
                    help='also build and run MAC27 at 0x140000000')
    ap.add_argument('--evidence', default=None)
    args = ap.parse_args()
    configs = list(CONFIGS)
    if args.high_base:
        configs.append(('MAC27', HIGH_BASE))
    dest = Path(args.out)
    dest.mkdir(parents=True, exist_ok=True)
    builds = [] if args.skip_build else build(configs, dest)
    if args.skip_build:
        builds = [dict(profile=p, base=b, build=rel(build_dir(p, b)),
                       log='reused') for p, b in configs]
    results = dict(builds=builds, sim=sim(configs, dest),
                   trace=trace(configs, dest) if args.trace else [])
    results['artifacts'] = sorted(
        rel(p) for p in dest.glob('*') if p.is_file())
    record = dict(results=results, wrote_evidence=False)
    if args.evidence:
        write_evidence(Path(args.evidence), results)
        record['wrote_evidence'] = True
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
