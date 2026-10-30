#!/usr/bin/env python3
"""C16 hostile-pointer protection control for the integrated SGX-KMS enclave.

The benign session fixture reaches the unchanged `ecall_proc_ma` with a real
current-session RA/GCM prefix.  This control keeps that prefix and changes only
the raw `void *` copied through the original `[in] void **c_p_net_ctxt` slot:

  control     a host sp_db_item_t with a known key (must pass in every profile)
  cd-app      the image's own protected global g_secret (zero key)
  cd-trusted  the pinned SDK RA database item's sk_key (the current session SK)

BASELINE has no pointer instrumentation and consumes each chosen key; the host
verifies both outgoing C16 ciphertexts with that key.  RADIX_ONLY and MAC27
must reject the raw enclave key range in the checked GCM adapter before the SDK
reads it.  The functional host is rerun as a regression.

SDK SIM only.  No hardware, secret extraction, full SGX-KMS deployment or
general arbitrary-address claim.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SDK = Path(os.environ.get(
    'SGX_SDK',
    str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
DEFAULT_BUILD = ROOT / 'build/sgx-kms/session-c16-2026-10-23'
MODES = ('control', 'cd-app', 'cd-trusted')
EXPECTED_LAYOUT = '1088 496 512 528'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def run(dest, name, command, env=None, cwd=None, timeout=900):
    proc = subprocess.run([str(x) for x in command], capture_output=True,
                          text=True, env=env, cwd=cwd, timeout=timeout)
    dest.mkdir(parents=True, exist_ok=True)
    log = dest / (name + '.log')
    log.write_text(proc.stdout + proc.stderr)
    return dict(command=[str(x) for x in command],
                returncode=proc.returncode, log=rel(log),
                log_sha256=sha(log),
                stdout=proc.stdout, stderr=proc.stderr)


def env_for(base):
    return dict(os.environ, ENCBOUND_TEST_BASE=base,
                LD_LIBRARY_PATH=str(SDK / 'sdk_libs') + ':' +
                               str(SDK / 'lib64'))


def result_rows(build):
    record = json.loads((build / 'results.json').read_text())
    rows = []
    for row in record['rows']:
        profile, base = row['profile'], row['base']
        directory = build / (profile + '-' + base)
        signed = directory / 'enclave.signed.so'
        assert signed.is_file(), signed
        assert sha(signed) == row['signed_sha256'], ('signed image changed', signed)
        rows.append(dict(profile=profile, base=base, directory=directory,
                         signed=signed, row=row))
    return record, rows


def elf_symbol(image, wanted):
    """Return (value, section name) for an exact .symtab/.strtab symbol."""
    symbols = subprocess.check_output(['readelf', '-sW', str(image)],
                                      text=True)
    value = index = None
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[-1] == wanted:
            value = int(fields[1], 16)
            index = int(fields[6])
            break
    if value is None:
        raise SystemExit('symbol not found: ' + wanted)
    sections = subprocess.check_output(['readelf', '-SW', str(image)],
                                       text=True)
    pattern = re.compile(r'\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-fA-F]+)')
    for line in sections.splitlines():
        match = pattern.match(line)
        if match and int(match.group(1)) == index:
            return value, match.group(2)
    raise SystemExit('section not found for ' + wanted)


def check_layout(dest):
    source = dest / 'ra_layout'
    build = run(dest, 'layout-build', ['gcc', '-I' + str(SDK / 'include'),
                                       HERE / 'c16_layout.c', '-o', source])
    if build['returncode']:
        raise SystemExit('layout build failed: ' + build['log'])
    result = run(dest, 'layout-run', [source])
    if result['returncode'] or result['stdout'].strip() != EXPECTED_LAYOUT:
        raise SystemExit('pinned RA layout changed: %r != %r'
                         % (result['stdout'].strip(), EXPECTED_LAYOUT))
    return dict(expected=EXPECTED_LAYOUT, observed=result['stdout'].strip(),
                log=result['log'], log_sha256=result['log_sha256'])


def build_host(dest, row):
    name = row['profile'] + '-' + row['base']
    generated = row['directory'] / 'generated'
    host = dest / name / 'c16-control-host'
    host.parent.mkdir(parents=True, exist_ok=True)
    command = ['gcc', '-g', '-O2', '-Wno-deprecated-declarations',
               '-I' + str(generated), '-I' + str(row['directory'].parent / 'source'),
               '-I' + str(SDK / 'include'), HERE / 'c16_control_host.c',
               generated / 'enclave_u.c', '-o', host,
               '-L' + str(SDK / 'lib64'),
               '-Wl,-rpath-link,' + str(SDK / 'lib64'),
               '-lsgx_urts_sim', '-lpthread', '-lcrypto']
    result = run(dest, name + '-host-build', command)
    if result['returncode']:
        raise SystemExit('control host build failed: ' + result['log'])
    return host, result


def parse_result(text):
    for line in reversed(text.splitlines()):
        if line.startswith('{'):
            return json.loads(line)
    return None


def run_modes(dest, rows):
    out = []
    for row in rows:
        name = row['profile'] + '-' + row['base']
        work = dest / name
        functional = run(work, 'functional',
                         [row['directory'] / 'host', row['signed']],
                         env=env_for(row['base']))
        if functional['returncode'] or \
                'SGX-KMS C16 BENIGN SIM PASS' not in functional['stdout']:
            raise SystemExit('functional regression failed: ' + functional['log'])
        host, build = build_host(dest, row)
        app_value, app_section = elf_symbol(row['signed'], 'g_secret')
        ra_value, ra_section = elf_symbol(row['signed'], '_ZL7g_ra_db')
        if row['profile'] != 'BASELINE':
            assert app_section == '.encbound.globalbss', app_section
            assert ra_section == '.bss', ra_section
        entry = dict(profile=row['profile'], base=row['base'],
                     signed=rel(row['signed']), signed_sha256=sha(row['signed']),
                     host=rel(host), host_sha256=sha(host),
                     targets=dict(
                         app=dict(symbol='g_secret', section=app_section,
                                  address=hex(int(row['base'], 16) + app_value)),
                         trusted=dict(symbol='_ZL7g_ra_db',
                                      vector_section=ra_section,
                                      vector_address=hex(int(row['base'], 16) + ra_value),
                                      item_key_offset=512)),
                     commands=[build], functional={
                         k: functional[k] for k in
                         ('command', 'returncode', 'log', 'log_sha256')},
                     modes={})
        for mode in MODES:
            name = row['profile'] + '-' + row['base'] + '-' + mode
            result = run(work, name, [host, row['signed'], mode],
                         env=env_for(row['base']), cwd=work)
            parsed = parse_result(result['stdout'])
            if mode == 'control':
                if result['returncode'] or not parsed or \
                        not parsed.get('nonce_verified'):
                    raise SystemExit('benign host control failed: ' +
                                     result['log'])
            elif row['profile'] == 'BASELINE':
                if result['returncode'] or not parsed or \
                        not parsed.get('nonce_verified'):
                    raise SystemExit('BASELINE hostile target did not consume '
                                     'the key: ' + result['log'])
            else:
                if result['returncode'] != -4:
                    raise SystemExit('expected SIGILL for %s, got %d: %s' %
                                     (mode, result['returncode'], result['log']))
                if parsed and parsed.get('stage') != 'target':
                    raise SystemExit('protected hostile run produced a result: '
                                     + result['log'])
            entry['modes'][mode] = {
                k: result[k] for k in
                ('command', 'returncode', 'log', 'log_sha256')}
            entry['modes'][mode]['result'] = parsed
        out.append(entry)
    return out


def trace(dest, rows):
    out = []
    for row in rows:
        if row['profile'] == 'BASELINE':
            continue
        work = dest / (row['profile'] + '-' + row['base'])
        for mode in ('cd-app', 'cd-trusted'):
            name = row['profile'] + '-' + row['base'] + '-' + mode + '-gdb'
            script = work / (name + '.gdb')
            script.write_text(
                'set pagination off\n'
                'set confirm off\n'
                'handle SIGILL stop print\n'
                'break kms_c16_ready\n'
                'run\n'
                'add-symbol-file %s -o %s\n'
                'continue\n'
                'bt 10\n' % (row['directory'] / 'enclave.so', row['base']))
            result = run(work, name,
                         ['gdb', '-q', '-batch', '-x', script, '--args',
                          work / 'c16-control-host', row['signed'], mode],
                         env=env_for(row['base']), cwd=work)
            text = result['stdout'] + result['stderr']
            need = ['encbound_abort (code=3)', 'encbound_require',
                    'encbound_kms_encrypt', 'server_put_secret_data',
                    'ecall_proc_ma', 'isv_enclave.cpp:669']
            missing = [value for value in need if value not in text]
            if missing:
                raise SystemExit('attribution missing %s: %s'
                                 % (missing, result['log']))
            target = re.search(r'"target":"(0x[0-9a-f]+)"', text)
            key = re.search(r'plain_ra_key=(0x[0-9a-f]+)', text)
            if not target or not key:
                raise SystemExit('missing hostile target/key line: ' +
                                 result['log'])
            if mode == 'cd-app' and '<g_secret>' not in text:
                raise SystemExit('cd-app key did not resolve to g_secret: ' +
                                 result['log'])
            out.append(dict(profile=row['profile'], base=row['base'],
                            mode=mode, target=target.group(1),
                            resolved_key=key.group(1),
                            abort_code=3,
                            enforcing_check='encbound_kms_encrypt span(key,16)',
                            source_line='source/isv_enclave.cpp:669',
                            script=rel(script), log=result['log'],
                            log_sha256=result['log_sha256'],
                            excerpt=[line for line in text.splitlines()
                                     if any(value in line for value in need)]))
    return out


def write_evidence(path, build_record, results):
    record = dict(
        date=datetime.now().astimezone().date().isoformat(),
        observed_at=datetime.now(timezone.utc).isoformat(),
        application='cloud-security-research/sgx-kms selected C16 service',
        pin=build_record['upstream'],
        scope='SDK SIM hostile pointer control at the unchanged C16 key use; '
              'no hardware, secret extraction, full deployment or '
              'arbitrary-address claim',
        unchanged_c16_body_sha256=build_record['unchanged_c16_body_sha256'],
        finding=dict(
            edl='isv_enclave/isv_enclave.edl:81 [in] void **c_p_net_ctxt',
            sink=['source/isv_enclave.cpp:665 '
                  'sp_db = (sp_db_item_t *)*c_p_net_ctxt',
                  'source/isv_enclave.cpp:669 '
                  'server_put_secret_data(..., (uint8_t *)&sp_db->sk_key, ...)'],
            primitive='the host chooses the raw sp_db_item_t pointer; the '
                      'unchanged body takes &sp_db->sk_key and uses it as the '
                      'GCM key for both outgoing C16 payloads',
            benign='a host sp_db_item_t with a known key is accepted in every '
                   'profile; both outgoing ciphertexts decrypt under that key',
            protected='RADIX_ONLY/MAC27 reject the raw protected-global or '
                      'trusted-RA-key range in encbound_kms_encrypt with '
                      'ENCBOUND_ERR_POLICY (code=3) before the SDK reads it'),
        ra_layout=results['ra_layout'], rows=results['rows'],
        gdb_attribution=results['trace'],
        inputs={rel(path): sha(path) for path in
                (HERE / 'c16_control_host.c', HERE / 'c16_protection.py',
                 HERE / 'c16_layout.c', HERE / 'adapters.c')},
        notes=['The valid current-session RA/message-2 and message-4 GCM prefix '
               'is reused unchanged; only c_p_net_ctxt names a different key.',
               'cd-app targets the image own zero-initialized g_secret global; '
               'cd-trusted targets the pinned SDK RA item sk_key, whose value '
               'is the peer-derived session SK.',
               'The host finds symbols in the image .symtab and reads the '
               'simulated process mapped g_ra_db vector; this is a test '
               'premise, not a production address leak.',
               'The functional 103-ECALL benign host still passes in all four '
               'configurations, including six successful C16 calls.'],
        limits=['SDK SIM only; no SGX hardware isolation.',
                'No arbitrary-address sweep, general secret extraction or code '
                'execution is claimed.',
                'The hostile target is one 16-byte key range per mode; both '
                'protected profiles reject the unchanged raw pointer.',
                'Full original-host message-3/quote/IAS, PSE, Barbican, '
                'hardware, cleanup/exhaustion and performance remain '
                'unestablished.'])
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--build', type=Path, default=DEFAULT_BUILD)
    args.add_argument('--out', type=Path,
                      default=ROOT / 'build/sgx-kms/c16-protection')
    args.add_argument('--trace', action='store_true',
                      help='run gdb attribution for both protected targets')
    args.add_argument('--evidence', type=Path, default=None)
    args = args.parse_args()
    build = args.build.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build_record, rows = result_rows(build)
    results = dict(ra_layout=check_layout(out))
    results['rows'] = run_modes(out, rows)
    results['trace'] = trace(out, rows) if args.trace else []
    results['artifacts'] = sorted(
        rel(path) for path in out.rglob('*') if path.is_file())
    record = dict(results=results, wrote_evidence=False)
    if args.evidence:
        write_evidence(args.evidence, build_record, results)
        record['wrote_evidence'] = True
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
