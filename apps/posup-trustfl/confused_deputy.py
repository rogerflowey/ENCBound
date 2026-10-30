#!/usr/bin/env python3
"""Direct [user_check] pointer-forgery control for the selected POSUP and
TrustFL ECALLs.

The unchanged EDL declarations are:

    POSUP    Enclave/Enclave.edl:18  ecall_getPathID([user_check] TYPE_ID*)
             Enclave/Enclave.edl:48  ecall_setFileIDs([user_check] uchar*, int)
    TrustFL  Enclave/Enclave.edl:17  ecall_data_preprocess(
                 [user_check] uchar* p_datau, uint, [user_check] uchar* p_labelu,
                 uint, unsigned long p_training_hmacu)

[user_check] passes the host-chosen raw pointer with no bridge copy, length,
null, canonical or outside-enclave check.  The unchanged bodies store, read and
copy through those pointers (prepared/Enclave.cpp:10,19 and :40,41,45).

`confused_deputy_host.c` names addresses inside the loaded enclave image:

  * POSUP  cd-read   setFileIDs reads a stable .data word pair from the image
                     and the observation ECALL returns it to the host;
           cd-write  getPathID stores pathID over the first word.
  * TrustFL cd-read  the 60,000 label bytes come from image .text and every
                     HMAC is checked by the host;
           cd-write  the 60,000 HMACs (1,920,000 bytes) are written to a mapped
                     span inside the enclave extent;
           cd-read-data  the training-data loop reads image .text and faults at
                     the mapped-image boundary; a child isolates the fault and
                     the parent checks the completed HMACs.

BASELINE performs the accesses.  RADIX_ONLY/MAC27 must reject the first raw
enclave address in encbound_require/encbound_abort before it is used.  The
`control` mode runs the same ECALLs with host buffers and must pass everywhere.
The existing functional host is re-run as a regression row.
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
CONFIGS = [('BASELINE', BASE), ('RADIX_ONLY', BASE), ('MAC27', BASE),
           ('MAC27', '0x140000000')]
MODES = {
    'POSUP': ['control', 'cd-read', 'cd-write'],
    'TrustFL': ['control', 'cd-read', 'cd-write', 'cd-read-data'],
}
# Modes whose BASELINE run must return 0 with this token in the JSON line.
PASS_TOKEN = {
    ('POSUP', 'control'): '"readback":"PASS"',
    ('POSUP', 'cd-read'): '"readback":"PASS"',
    ('POSUP', 'cd-write'): '"write":"PASS"',
    ('TrustFL', 'control'): '"macs":"PASS"',
    ('TrustFL', 'cd-read'): '"macs":"PASS"',
    ('TrustFL', 'cd-write'): '"macs":"PASS"',
    ('TrustFL', 'cd-read-data'): '"macs":"PASS"',
}
# Protected attribution: source line and the checked adapter in the frame.
ATTRIBUTION = {
    ('POSUP', 'cd-read'): ('ecall_setFileIDs', 'encbound_memcpy',
                           'prepared/Enclave.cpp:19'),
    ('POSUP', 'cd-write'): ('ecall_getPathID', 'encbound_require',
                            'prepared/Enclave.cpp:10'),
    ('TrustFL', 'cd-read'): ('ecall_data_preprocess', 'encbound_require',
                             'prepared/Enclave.cpp:41'),
    ('TrustFL', 'cd-write'): ('ecall_data_preprocess', 'encbound_require',
                              'prepared/Enclave.cpp:45'),
    ('TrustFL', 'cd-read-data'): ('ecall_data_preprocess', 'encbound_memcpy',
                                  'prepared/Enclave.cpp:40'),
}
BUILD_ROOT = ROOT / 'build/posup-trustfl/all-compat-v1-final'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def label(profile, base):
    return profile + ('-high' if base != BASE else '')


def row_dir(app, profile, base):
    return BUILD_ROOT / app / label(profile, base)


def run(dest, name, command, env=None, timeout=3600):
    proc = subprocess.run([str(x) for x in command], capture_output=True,
                          text=True, env=env, timeout=timeout)
    dest.mkdir(parents=True, exist_ok=True)
    log = dest / (name + '.log')
    log.write_text(proc.stdout + proc.stderr)
    return dict(command=[str(x) for x in command],
                returncode=proc.returncode, log=rel(log),
                log_sha256=sha(log), stdout=proc.stdout, stderr=proc.stderr)


def env_for(base):
    return dict(os.environ, ENCBOUND_TEST_BASE=base,
                LD_LIBRARY_PATH=str(SDK / 'lib64') + ':' +
                               str(SDK / 'sdk_libs'))


def host_binary(app, profile, base, dest):
    row = row_dir(app, profile, base)
    out = dest / app / label(profile, base) / 'cd-host'
    out.parent.mkdir(parents=True, exist_ok=True)
    r = run(dest, 'build-' + app + '-' + label(profile, base),
            ['cc', '-O2', '-g', '-w', '-DAPP_' + app.upper(),
             '-I' + str(row / 'prepared'), '-I' + str(row / 'generated'),
             '-I' + str(SDK / 'include'), HERE / 'confused_deputy_host.c',
             row / 'generated/Enclave_u.c', '-L' + str(SDK / 'lib64'),
             '-Wl,-rpath-link,' + str(SDK / 'lib64'), '-lsgx_urts_sim',
             '-lpthread', '-lcrypto', '-o', out])
    if r['returncode']:
        raise SystemExit('host build failed: ' + r['log'])
    return out, r


def sim(dest):
    rows = []
    for app, modes in MODES.items():
        for profile, base in CONFIGS:
            row = row_dir(app, profile, base)
            if not (row / 'enclave/enclave.signed.so').is_file():
                raise SystemExit('missing saved row ' + str(row) +
                                 '; run apps/posup-trustfl/run.py first')
            host, build_log = host_binary(app, profile, base, dest)
            entry = dict(app=app, profile=profile, base=base,
                         host=rel(host), host_build_log=build_log['log'],
                         host_build_sha256=build_log['log_sha256'],
                         signed=rel(row / 'enclave/enclave.signed.so'),
                         signed_sha256=sha(row / 'enclave/enclave.signed.so'),
                         build_record_sha256=sha(row / 'build.json'),
                         prepared_sha256=sha(row / 'prepared/Enclave.cpp'),
                         modes={})
            # Functional host regression, separate from the forgery claim.
            r = run(dest, app + '-' + label(profile, base) + '-functional',
                    [row / 'host', row / 'enclave/enclave.signed.so'],
                    env=env_for(base))
            expected = dict(result='PASS',
                            calls=54 if app == 'POSUP' else 5,
                            comparisons=234 if app == 'POSUP' else 5820000)
            line = next((ln for ln in r['stdout'].splitlines()
                         if ln.startswith('{')), '{}')
            response = json.loads(line)
            if r['returncode'] or response != expected:
                raise SystemExit('functional host failed: ' + r['log'])
            entry['modes']['functional'] = {k: r[k] for k in
                                            ('command', 'returncode', 'log',
                                             'log_sha256')}
            for mode in modes:
                r = run(dest, app + '-' + label(profile, base) + '-' + mode,
                        [host, row / 'enclave/enclave.signed.so', mode],
                        env=env_for(base))
                if mode == 'control':
                    if r['returncode'] or PASS_TOKEN[(app, mode)] not in r['stdout']:
                        raise SystemExit('control failed: ' + r['log'])
                elif profile == 'BASELINE':
                    if r['returncode'] or PASS_TOKEN[(app, mode)] not in r['stdout']:
                        raise SystemExit('baseline %s failed: %s' %
                                         (mode, r['log']))
                    if mode == 'cd-read-data' and \
                            '"child_signal":11' not in r['stdout']:
                        raise SystemExit('expected a child SIGSEGV: ' + r['log'])
                else:
                    if r['returncode'] != -4:
                        raise SystemExit('expected SIGILL in %s/%s/%s, got %d: %s'
                                         % (app, label(profile, base), mode,
                                            r['returncode'], r['log']))
                entry['modes'][mode] = {k: r[k] for k in
                                        ('command', 'returncode', 'log',
                                         'log_sha256')}
                entry['modes'][mode]['stdout'] = r['stdout'].strip()
            rows.append(entry)
    return rows


def trace(dest):
    rows = []
    for app, modes in MODES.items():
        for profile, base in CONFIGS:
            if profile == 'BASELINE':
                continue
            row = row_dir(app, profile, base)
            host = dest / app / label(profile, base) / 'cd-host'
            for mode in modes:
                if mode == 'control':
                    continue
                function, adapter, source_line = ATTRIBUTION[(app, mode)]
                script = dest / ('attr-' + app + '-' + label(profile, base) +
                                 '-' + mode + '.gdb')
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text(
                    'set pagination off\nset confirm off\n'
                    + ('set follow-fork-mode child\n'
                       if mode == 'cd-read-data' else '')
                    + 'handle SIGILL stop print\n'
                    'break posup_trustfl_cd_ready\nrun\n'
                    'add-symbol-file %s -o %s\ncontinue\nbt 12\n' %
                    (row / 'enclave/enclave.so', base))
                r = run(dest, 'attr-' + app + '-' + label(profile, base) + '-' +
                        mode, ['gdb', '-q', '-batch', '-x', script, '--args',
                               host, row / 'enclave/enclave.signed.so', mode],
                        env=env_for(base))
                text = r['stdout'] + r['stderr']
                need = ['encbound_abort (code=3)', adapter, function,
                        source_line]
                missing = [n for n in need if n not in text]
                if missing:
                    raise SystemExit('attribution missing %s for %s/%s/%s: %s' %
                                     (missing, app, label(profile, base), mode,
                                      r['log']))
                rows.append(dict(app=app, profile=profile, base=base, mode=mode,
                                 abort_code=3, adapter=adapter,
                                 source_line=source_line, script=rel(script),
                                 log=r['log'], log_sha256=r['log_sha256'],
                                 excerpt=[l for l in text.splitlines()
                                          if any(n in l for n in need)]))
    return rows


def write_evidence(path, results):
    record = dict(
        date=datetime.now().astimezone().date().isoformat(),
        observed_at=datetime.now(timezone.utc).isoformat(),
        application=['thanghoang/POSUP required ECALLs',
                     'zeyu-zh/TrustFL required ECALLs'],
        pin=['9a6e181763535fd927bca1749cd804e5d77f2f73',
             '9e05a7e160bbf4fa1e7a426767f69158ea89b22d'],
        scope='SDK SIM direct [user_check] pointer forgery; no hardware, '
              'unbounded exploit, secret extraction or full-workflow claim',
        finding=dict(
            edl=['POSUP Enclave/Enclave.edl:18 ecall_getPathID',
                 'POSUP Enclave/Enclave.edl:48 ecall_setFileIDs',
                 'TrustFL Enclave/Enclave.edl:17 ecall_data_preprocess'],
            sink=['POSUP prepared/Enclave.cpp:10 *output = pathID;',
                  'POSUP prepared/Enclave.cpp:19 memcpy(&tmp, &fid_arr[...], 4)',
                  'TrustFL prepared/Enclave.cpp:40 memcpy(p_data_label, p_datau, 784)',
                  'TrustFL prepared/Enclave.cpp:41 p_data_label[784] = *p_labelu',
                  'TrustFL prepared/Enclave.cpp:45 p_hmacu[i] = temp'],
            primitive='host-supplied [user_check] pointers are dereferenced '
                      'without an outside-enclave or range check; the host can '
                      'name enclave-internal addresses for application reads '
                      'and writes',
            baseline='POSUP stores pathID over a .data word and reads a .data '
                     'word pair; TrustFL reads 60,000 label bytes from image '
                     '.text, writes 1,920,000 HMAC bytes into a mapped span, '
                     'and reads a byte-verified 223,440-byte image prefix as '
                     'training data (the fixed 47 MB loop then faults at the '
                     'mapped-image boundary)',
            protected='RADIX_ONLY/MAC27 abort in encbound_require/'
                      'encbound_memcpy with ENCBOUND_ERR_POLICY (code=3) at '
                      'the first raw enclave address'),
        control_source=dict(
            host=rel(HERE / 'confused_deputy_host.c'),
            host_sha256=sha(HERE / 'confused_deputy_host.c'),
            runner=rel(HERE / 'confused_deputy.py'),
            runner_sha256=sha(HERE / 'confused_deputy.py')),
        hosts=[{k: row[k] for k in ('app', 'profile', 'base', 'host',
                                    'host_build_log', 'host_build_sha256',
                                    'signed', 'signed_sha256',
                                    'build_record_sha256', 'prepared_sha256')}
               for row in results['sim']],
        sim=results['sim'],
        gdb_attribution=results['trace'],
        notes=['POSUP targets a stable .data version-string word pair; the '
               'first .data word is the SDK g_is_first_ecall flag and is not '
               'used.',
               'TrustFL label and training-data reads use image .text.  The '
               'fixed 47 MB training-data loop continues past the verified '
               'prefix and faults at the mapped-image boundary, so the child '
               'fault is isolated and every byte of the stable read-only '
               'prefix is checked.',
               'TrustFL output targets the largest loaded read-write mapping '
               'inside the enclave extent (reserved memory); only BASELINE '
               'reaches the store.'],
        limits=['SDK SIM only; no SGX hardware.',
                'No arbitrary-address sweep, secret extraction or code '
                'execution is claimed.',
                'The host knows the enclave base and image layout in SIM, as a '
                'loader does; this is a demonstration premise, not a '
                'production address leak.',
                'The read primitive returns HMACs of enclave memory, not the '
                'plaintext bytes; it is an equality/verification oracle with '
                'the known pre-init key.'])
    Path(path).write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'build/posup-trustfl/confused-deputy'))
    ap.add_argument('--trace', action='store_true',
                    help='also run gdb attribution for protected profiles')
    ap.add_argument('--evidence', default=None)
    args = ap.parse_args()
    dest = Path(args.out)
    dest.mkdir(parents=True, exist_ok=True)
    results = dict(sim=sim(dest),
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
