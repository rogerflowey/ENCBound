#!/usr/bin/env python3
"""Hostile C01 two-call stateful buffer-pool control in SDK simulation.

This runs the unchanged selected Crust `ecall_safe_store2` twice with the same
`buffer_key`:

  1. total_size=0x100, partial_size=1, offset=0  (retains a 256-byte buffer)
  2. total_size=0x1000, partial_size=0x400, offset=0x800

The second call reuses the 256-byte allocation and the original body calls
`memcpy(buffer + 0x800, data, 0x400)`.  Neither call completes the transfer, so
the terminal restore stub is not reached.  BASELINE executes the unchecked
write; RADIX_ONLY/MAC27 should stop in the checked destination range.

The existing `apps/crust-selected/run.py` integration matrix supplies the four
images.  This runner compiles a separate driver against those images and does
not modify the application, EDL, bridge or generated code.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK',
    str(ROOT/'deps/sgxsdk'))).resolve()
DEFAULT_BUILDS = ROOT/'build/crust-selected/enclave-v1/all-compat-v1'
DEFAULT_OUT = ROOT/'build/crust-selected/c01-hostile-v1'
CONFIGS = [('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
           ('MAC27', '0x40000000'), ('MAC27', '0x140000000')]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def run(dest, name, command, env=None, timeout=600):
    command = [str(item) for item in command]
    proc = subprocess.run(command, cwd=ROOT, env=env, text=True,
                          capture_output=True, timeout=timeout)
    log = dest/(name+'.log')
    log.write_text(proc.stdout+proc.stderr)
    return dict(command=command, returncode=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr, log=str(log),
                log_sha256=sha(log))


def build_dir(builds, profile, base):
    return builds/(profile+'-'+base)


def host_env(base):
    return dict(os.environ,
                LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'),
                ENCBOUND_TEST_BASE=base)


def check_images(builds):
    missing = []
    for profile, base in CONFIGS:
        b = build_dir(builds, profile, base)
        if not (b/'enclave.signed.so').is_file() or not (b/'generated'/'enclave_u.c').is_file():
            missing.append(rel(b))
    return missing


def memcpy_address(image):
    output = subprocess.check_output(['nm', '--defined-only', str(image)],
                                     text=True)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == 'memcpy':
            return int(fields[0], 16)
    raise RuntimeError('no memcpy symbol in '+str(image))


def compile_driver(builds, out, profile, base):
    b = build_dir(builds, profile, base)
    dest = out/(profile+'-'+base)
    dest.mkdir(parents=True, exist_ok=True)
    command = ['gcc', '-O2', '-g', '-I'+str(b/'generated'), '-I'+str(builds/'source'),
        '-I'+str(SDK/'include'), HERE/'hostile.c', b/'generated'/'enclave_u.c',
        '-o', dest/'hostile', '-L'+str(SDK/'lib64'),
        '-Wl,-rpath-link,'+str(SDK/'lib64'), '-lsgx_urts_sim', '-lpthread']
    result = run(dest, 'compile', command, dict(os.environ))
    if result['returncode']:
        raise SystemExit('hostile driver did not compile: '+result['log'])
    return dest/'hostile', result


def trace_protected(dest, label, hostile, image, base):
    script = dest/(label+'-attribution.gdb')
    script.write_text(
        'set pagination off\nset confirm off\n'
        'handle SIGILL stop print\n'
        'break crust_c01_hostile_ready\nrun\n'
        'add-symbol-file %s -o %s\ncontinue\nbt 12\n' %
        (image, base))
    result = run(dest, label+'-attribution',
                 ['gdb', '-q', '-batch', '-x', script, '--args',
                  hostile, image], host_env(base))
    text = result['stdout']+result['stderr']
    required = ['encbound_abort (code=4)', 'encbound_require',
                'encbound_memcpy', 'n=1024', 'ecall_safe_store2',
                'first transport=0 app=0']
    missing = [item for item in required if item not in text]
    if missing:
        raise SystemExit('%s attribution missing %s: %s' %
                         (label, missing, result['log']))
    if 'second transport=0' in text:
        raise SystemExit('%s returned a second success after the abort: %s' %
                         (label, result['log']))
    assert re.search(r'width=(?:width@entry=)?1024', text), text
    assert re.search(r'kind=(?:kind@entry=)?2', text), text
    capability = re.search(r'capability=capability@entry=(0x[0-9a-f]+|\d+)', text)
    memcpy = re.search(r'encbound_memcpy \(dst=(0x[0-9a-f]+), '
                       r'src=(0x[0-9a-f]+), n=(\d+)\)', text)
    slot = {}
    if capability and memcpy:
        cap = int(capability.group(1), 0)
        radix = (cap >> 59) & 0x1f
        if 1 <= radix <= 30:
            slot = dict(slot_radix=radix, slot_bytes=1 << radix,
                        destination_offset=cap & 0xffffffff)
    excerpt = [line for line in text.splitlines()
               if any(item in line for item in required) or
               re.search(r'width=(?:width@entry=)?1024', line) or
               re.search(r'kind=(?:kind@entry=)?2', line)]
    return dict(mode='SIGILL', abort_code=4, width=1024,
                access='write', n=1024, script=str(script),
                **slot,
                log=result['log'], log_sha256=sha(result['log']),
                excerpt=excerpt)


def trace_baseline(dest, label, hostile, image, base):
    memcpy = memcpy_address(image)
    script = dest/(label+'-attribution.gdb')
    script.write_text(
        'set pagination off\nset confirm off\n'
        'break crust_c01_hostile_ready\nrun\n'
        'add-symbol-file %s -o %s\n'
        'break *(%#x + %s) if $rdx == 1024\n'
        # The first n=1024 hit is the generated bridge copying the input;
        # the second is the application memcpy in ecall_safe_store2.
        'ignore 2 1\ncontinue\n'
        'set $dst = $rdi\nset $src = $rsi\n'
        'printf "application memcpy n=%%lu dst=%%p src=%%p\\n", $rdx, $dst, $src\n'
        'x/8bx $dst\nx/8bx $src\nbt 5\nfinish\n'
        'printf "after application memcpy:\\n"\nx/8bx $dst\ncontinue\n' %
        (image, base, memcpy, base))
    result = run(dest, label+'-attribution',
                 ['gdb', '-q', '-batch', '-x', script, '--args',
                  hostile, image], host_env(base))
    text = result['stdout']+result['stderr']
    required = ['application memcpy n=1024', 'ecall_safe_store2',
                'after application memcpy', 'second transport=0 app=0']
    missing = [item for item in required if item not in text]
    if missing:
        raise SystemExit('%s attribution missing %s: %s' %
                         (label, missing, result['log']))
    # The payload starts with 0x03 0x0a 0x11 ...; the destination is within a
    # 256-byte allocation and must be zero before the unchecked copy.
    match = re.search(r'application memcpy n=1024 dst=(0x[0-9a-f]+) '
                      r'src=(0x[0-9a-f]+)\n'
                      r'(0x[0-9a-f]+):\s+([0-9a-fx\t ]+)\n'
                      r'(0x[0-9a-f]+):\s+([0-9a-fx\t ]+)\n', text)
    if not match:
        raise SystemExit('%s could not parse the memcpy memory dump: %s' %
                         (label, result['log']))
    dst, src = match.group(1), match.group(2)
    before = re.findall(r'0x([0-9a-f]{2})', match.group(4))
    after_match = re.search(r'after application memcpy:\s*\n'
                            r'(0x[0-9a-f]+):\s+([0-9a-fx\t ]+)\n', text)
    if not after_match:
        raise SystemExit('%s missing post-memcpy memory dump: %s' %
                         (label, result['log']))
    after = re.findall(r'0x([0-9a-f]{2})', after_match.group(2))
    if before != ['00'] * 8 or after[:8] != ['03', '0a', '11', '18',
                                             '1f', '26', '2d', '34']:
        raise SystemExit('%s unexpected before/after bytes %s -> %s: %s' %
                         (label, before, after, result['log']))
    excerpt = [line for line in text.splitlines()
               if any(item in line for item in required) or
               'application memcpy' in line or
               line.startswith('0x') or line.startswith('#')]
    return dict(mode='return',
                application_memcpy=dict(n=1024, call_site='ecall_safe_store2',
                                        destination=dst, source=src,
                                        before_bytes=before, after_bytes=after),
                script=str(script), log=result['log'],
                log_sha256=sha(result['log']), excerpt=excerpt)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builds', type=Path, default=DEFAULT_BUILDS)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--build', action='store_true',
                        help='run apps/crust-selected/run.py first')
    parser.add_argument('--evidence', type=Path, default=None,
                        help='write the machine-readable record here')
    args = parser.parse_args()
    builds = args.builds.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    missing = check_images(builds)
    if missing and not args.build:
        raise SystemExit('missing integration images: %s\n'
                         'run `python3 apps/crust-selected/run.py` or pass --build' %
                         ', '.join(missing))
    if args.build:
        result = run(out, 'integration-build',
                     ['python3', ROOT/'apps/crust-selected/run.py',
                      '--out-dir', builds], dict(os.environ), timeout=3600)
        if result['returncode']:
            raise SystemExit('integration build failed: '+result['log'])

    rows = []
    for profile, base in CONFIGS:
        label = profile+'-'+base
        b = build_dir(builds, profile, base)
        image = b/'enclave.signed.so'
        hostile, _ = compile_driver(builds, out, profile, base)
        config_out = out/label
        result = run(config_out, label+'-hostile', [hostile, image], host_env(base))
        text = result['stdout']+result['stderr']
        row = dict(profile=profile, base=base, mode='SDK SIM',
                   image=rel(image), image_sha256=sha(image),
                   build_manifest=rel(b/'build.json'),
                   build_manifest_sha256=sha(b/'build.json'),
                   driver=rel(hostile), run=result, expected=None)
        if profile == 'BASELINE':
            if result['returncode'] != 0:
                raise SystemExit('%s hostile run returned %d: %s' %
                                 (label, result['returncode'], result['log']))
            response = json.loads(next(line for line in result['stdout'].splitlines()
                                       if line.startswith('{')))
            assert response == dict(mode='hostile', first=[0, 0], second=[0, 0],
                                    total_size=0x1000, partial_size=0x400,
                                    offset=0x800), response
            row['expected'] = 'both calls return CRUST_SUCCESS; unchecked write executes'
            row['response'] = response
            row['attribution'] = trace_baseline(config_out, label, hostile, image, base)
        else:
            if result['returncode'] != -signal.SIGILL:
                raise SystemExit('%s expected SIGILL, got %d: %s' %
                                 (label, result['returncode'], result['log']))
            if 'first transport=0 app=0' not in text:
                raise SystemExit('%s did not complete the first call: %s' %
                                 (label, result['log']))
            if 'second transport=' in text:
                raise SystemExit('%s printed a second status: %s' %
                                 (label, result['log']))
            row['expected'] = 'SIGILL at the checked destination range'
            row['attribution'] = trace_protected(config_out, label, hostile, image, base)
        rows.append(row)
        (out/'results.json').write_text(json.dumps(dict(
            scope='hostile C01 two-call stateful buffer-pool control; SDK SIM',
            builds=rel(builds), rows=rows, hardware=False,
            performance=False), indent=2)+'\n')
        print(label, row['expected'], flush=True)

    protected_rows = [row for row in rows if row['profile'] != 'BASELINE']
    offsets = sorted({row['attribution'].get('destination_offset')
                      for row in protected_rows
                      if row['attribution'].get('destination_offset') is not None})
    offset_text = ', '.join(hex(value) for value in offsets) or 'unrecorded'
    slot_radix = protected_rows[0]['attribution'].get('slot_radix', 'unrecorded')
    slot_bytes = protected_rows[0]['attribution'].get('slot_bytes', 'unrecorded')
    record = dict(
        date=datetime.now().astimezone().date().isoformat(),
        observed_at=datetime.now(timezone.utc).isoformat(),
        application='crustio/crust-sworker selected ecall_safe_store2 '
                    '(nontrivial-ingress-bugs C01)',
        pin=json.loads((HERE/'pins.json').read_text())['revision'],
        scope='SDK SIM hostile C01 two-call stateful buffer-pool control; no hardware, '
              'exploit, unbounded-write, restore-completion or full-deployment claim',
        sequence=dict(buffer_key='0x434f3031', type='ECALL_RESTORE_FROM_UPGRADE',
                      first=dict(total_size=0x100, partial_size=1, offset=0),
                      second=dict(total_size=0x1000, partial_size=0x400, offset=0x800),
                      completion=False),
        builds=rel(builds),
        tooling=dict(driver=rel(HERE/'hostile.c'),
                     driver_sha256=sha(HERE/'hostile.c'),
                     runner_sha256=sha(Path(__file__))),
        rows=rows,
        result=dict(
            baseline='both calls return CRUST_SUCCESS; gdb observes the raw '
                     '1,024-byte memcpy from ecall_safe_store2 at the second '
                     'call\'s offset 0x800 and the destination changes from '
                     'zeros to the payload',
            protected='RADIX_ONLY/MAC27 at both image bases terminate with SIGILL; '
                      'gdb attributes to encbound_abort(code=4), encbound_require '
                      'width=1024 kind=2, encbound_memcpy n=1024 and ecall_safe_store2; '
                      'the rejected capability has radix %s (%s-byte slot) and '
                      'destination offset %s = first-call buffer + 0x800' %
                      (slot_radix, slot_bytes, offset_text),
            callback='not reached because offset+partial_size < total_size in both calls'),
        limits=[
            'SDK simulation only; no SGX hardware result.',
            'The 0x400-byte write is a bounded control. Its later heap effects are '
            'not characterized and no secret reachability, crash or exploit is claimed.',
            'The terminal restore stub remains in place; completed-transfer cleanup '
            'and real restore are outside this control.',
            'The control is serial with one TCS and the recorded no-op mutex stubs; '
            'no concurrent or reentrant workload is admitted.',
            'Same-key reuse and the 256-byte slot are established by the pinned '
            'source and the protected width-1024 rejection, not by exporting pointers.'
        ])
    (out/'evidence.json').write_text(json.dumps(record, indent=2)+'\n')
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(record, indent=2)+'\n')
    print('C01 HOSTILE CONTROL PASS:', len(rows), 'configurations', flush=True)


if __name__ == '__main__':
    main()
