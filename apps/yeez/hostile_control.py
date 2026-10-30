#!/usr/bin/env python3
"""C13/C14 hostile `next_data_batch` control through the original public path.

The original raw and sealed multi-person analyzers call `next_data_batch` and
then copy the returned host pointer/length into an enclave buffer.  This runner
keeps the original ECALL, EDL, provider, bridge and runtime bodies unchanged and
changes only the untrusted host callback: for the first batch it returns a raw
pointer into the analyzer enclave's protected application data instead of a host
buffer.

BASELINE executes the application `memcpy` and copies the protected bytes.
RADIX_ONLY/MAC27 should stop in the checked source read before the raw copy.
The driver reuses the signed images produced by `apps/yeez/execute.py` from the
audited `build/yeez/full-integration` images.  It signs into a separate
directory so the normal raw/sealed/empty evidence is not overwritten.
"""
import argparse
import hashlib
import json
import os
import re
import resource
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK',
    ROOT/'deps/sgxsdk')).resolve()
BUILD = ROOT/'build/yeez/full-integration'
DEFAULT_OUT = ROOT/'build/yeez/c13-hostile-v1'
CONFIGS = [('BASELINE', False), ('RADIX_ONLY', False),
           ('MAC27', False), ('MAC27', True)]
TARGET = 'aad_mac_text'
TARGET_LEN = 32
EXPECTED = b'tech.yeez.key.manager'  # first 21 bytes of the target object


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def run(dest, name, command, env=None, timeout=600):
    command = [str(item) for item in command]
    dest.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(command, cwd=ROOT, env=env, text=True,
                          capture_output=True, timeout=timeout)
    log = dest/(name+'.log')
    log.write_text(proc.stdout+proc.stderr)
    return dict(command=command, returncode=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr, log=str(log),
                log_sha256=sha(log))


def build_record(profile):
    path = BUILD/profile/'build.json'
    if not path.is_file():
        raise SystemExit('missing integration build: '+rel(path))
    record = json.loads(path.read_text())
    for kind in ('analyzer', 'keymgr'):
        image = Path(record['images'][kind]['image'])
        if sha(image) != record['images'][kind]['sha256']:
            raise SystemExit('unsigned image changed: '+rel(image))
    return record


def signed_record(profile, high, out, rebuild=False):
    dest = out/profile/('high' if high else 'low')
    execute = dest/'results.json'
    if rebuild or not execute.is_file() or not (dest/'host').is_file():
        command = [sys.executable, str(HERE/'execute.py'), '--profile', profile,
                   '--signed-out', str(dest), '--build-only']
        if high:
            command.append('--high')
        result = run(dest, 'execute-build', command)
        if result['returncode']:
            raise SystemExit('signing/host build failed: '+result['log'])
    result = json.loads(execute.read_text())
    if result.get('high') != high or result.get('profile') != profile:
        raise SystemExit('signed record profile/base mismatch: '+str(execute))
    for kind in ('analyzer', 'keymgr'):
        path = Path(result['signed'][kind]['image'])
        if sha(path) != result['signed'][kind]['sha256']:
            raise SystemExit('signed image changed: '+rel(path))
    if not (dest/'host').is_file():
        raise SystemExit('signed host missing: '+rel(dest/'host'))
    return result, dest


def symbol_offset(image, name):
    output = subprocess.check_output(['nm', '-C', '--defined-only', str(image)],
                                     text=True)
    matches = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == name:
            matches.append(int(fields[0], 16))
    if not matches:
        raise SystemExit('target symbol %s not found in %s' % (name, image))
    return matches[0]


def symbol_section(image, name, value):
    sections = {}
    raw = subprocess.check_output(['readelf', '-SW', str(image)], text=True)
    for line in raw.splitlines():
        match = re.match(r'\s*\[\s*(\d+)\]\s+(\S+)\s+', line)
        if match:
            sections[match.group(1)] = match.group(2)
    raw = subprocess.check_output(['readelf', '-sW', str(image)], text=True)
    for line in raw.splitlines():
        fields = line.split()
        if (len(fields) == 8 and name in fields[7] and
                int(fields[1], 16) == value):
            return sections.get(fields[6], '<unknown>')
    return '<unknown>'


def image_limit(image):
    raw = subprocess.check_output(['readelf', '-lW', str(image)], text=True)
    limit = 0
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[0] == 'LOAD':
            limit = max(limit, int(fields[2], 16)+int(fields[5], 16))
    return limit


def target(image, base):
    offset = symbol_offset(image, TARGET)
    if offset >= image_limit(image):
        raise SystemExit('target symbol outside image: %s' % TARGET)
    return dict(symbol=TARGET, offset=offset, pointer=base+offset,
                section=symbol_section(image, TARGET, offset))


def dump_bytes(block):
    values = []
    for line in block.splitlines():
        match = re.match(r'^0x[0-9a-f]+(?: <[^>]*>)?:\s+(.*)$', line)
        if match:
            values += [int(item, 16) for item in
                       re.findall(r'0x([0-9a-f]{2})\b', match.group(1))]
    return values


def baseline_script(image, base, target, checked):
    pointer = target['pointer']
    return (
        'set pagination off\nset confirm off\n'
        'handle SIGILL stop print\n'
        'break next_data_batch\nrun\n'
        'add-symbol-file %s -o %#x\n'
        'break *(%#x + %#x) if $rsi == %#x && $rdx == %d\n'
        'break *(%#x + %#x)\n'
        'commands\n'
        ' silent\n'
        ' printf "HOSTILE_BASELINE_ABORT_AFTER_COPY\\n"\n'
        ' bt 10\n'
        ' continue\n'
        'end\n'
        'continue\n'
        'printf "HOSTILE_MEMCPY\\n"\n'
        'bt 6\n'
        'x/%dbx $rsi\n'
        'set $dst=$rdi\n'
        'finish\n'
        'printf "HOSTILE_AFTER_COPY\\n"\n'
        'x/%dbx $dst\n'
        'continue\n' % (image, base, base, checked['memcpy'],
                        pointer, TARGET_LEN, base, checked['abort'],
                        TARGET_LEN, TARGET_LEN))


def protected_script(image, base, target, checked):
    pointer = target['pointer']
    return (
        'set pagination off\nset confirm off\n'
        'handle SIGILL stop print\n'
        'break next_data_batch\nrun\n'
        'add-symbol-file %s -o %#x\n'
        'break *(%#x + %#x) if $rsi == %#x && $rdx == %d\n'
        'break *(%#x + %#x)\n'
        'continue\n'
        'printf "HOSTILE_CHECKED_MEMCPY\\n"\n'
        'bt 6\n'
        'x/%dbx $rsi\n'
        'continue\n'
        'printf "HOSTILE_CHECKED_ABORT\\n"\n'
        'bt 8\n'
        'printf "HOSTILE_ABORT_CODE=%%d\\n", code\n'
        'continue\n' % (image, base, base, checked['encbound_memcpy'],
                        pointer, TARGET_LEN, base, checked['encbound_abort'],
                        TARGET_LEN))


def symbols(image, profile):
    checked = dict(memcpy=symbol_offset(image, 'memcpy'),
                   abort=symbol_offset(image, 'abort'))
    if profile != 'BASELINE':
        checked.update(encbound_memcpy=symbol_offset(image, 'encbound_memcpy'),
                       encbound_abort=symbol_offset(image, 'encbound_abort'))
    return checked


def check_dump(values, where):
    expected = list(EXPECTED)+[0]*(TARGET_LEN-len(EXPECTED))
    if values[:TARGET_LEN] != expected:
        raise SystemExit('%s does not contain the target bytes: %s' %
                         (where, values[:TARGET_LEN]))


def trace(dest, label, host, analyzer, keymgr, base, target, profile, mode,
          checked):
    script = dest/(label+'.gdb')
    if profile == 'BASELINE':
        script.write_text(baseline_script(analyzer, base, target, checked))
    else:
        script.write_text(protected_script(analyzer, base, target, checked))
    env = dict(os.environ,
               LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'),
               YEEZ_ANALYZER_BASE=hex(base),
               YEEZ_MANAGER_BASE='0x80000000' if base == 0x40000000 else '0x180000000',
               YEEZ_HOSTILE=mode, YEEZ_HOSTILE_PTR=hex(target['pointer']),
               YEEZ_HOSTILE_LEN=str(TARGET_LEN), YEEZ_VERBOSE='1')
    result = run(dest, label+'-gdb',
                 ['gdb', '-q', '-batch', '-x', str(script), '--args',
                  str(host), str(analyzer), str(keymgr)], env)
    text = result['stdout']+result['stderr']
    if profile == 'BASELINE':
        if 'HOSTILE_MEMCPY' not in text or 'HOSTILE_AFTER_COPY' not in text:
            raise SystemExit('%s did not stop at the application copy: %s' %
                             (label, result['log']))
        source = dump_bytes(text.split('HOSTILE_MEMCPY', 1)[1]
                                .split('HOSTILE_AFTER_COPY', 1)[0])
        copied = dump_bytes(text.split('HOSTILE_AFTER_COPY', 1)[1])
        check_dump(source, label+' source')
        check_dump(copied, label+' destination')
        if mode == 'raw':
            if ('YEEZ HOSTILE SURVIVED mode=raw' not in text or
                    'exited normally' not in text):
                raise SystemExit('%s raw baseline did not survive the copy: %s' %
                                 (label, result['log']))
            outcome = 'copied-and-survived'
            abort = None
        else:
            if ('HOSTILE_BASELINE_ABORT_AFTER_COPY' not in text or
                    'encbound_abort' in text):
                raise SystemExit('%s sealed baseline did not take the original '
                                 'EH abort path: %s' % (label, result['log']))
            if '__encbound_eh_entry_parse_data_item' not in text:
                raise SystemExit('%s sealed baseline abort lacks the EH frame: %s'
                                 % (label, result['log']))
            outcome = 'copied-then-original-eh-abort'
            abort = 'original-uncaught-exception'
        required = ['raw_data_provider::process' if mode == 'raw'
                    else 'sealed_data_provider', TARGET]
        if not all(item in text for item in required):
            raise SystemExit('%s copy attribution missing %s: %s' %
                             (label, required, result['log']))
        row = dict(outcome=outcome, abort=abort, source_bytes=source,
                   copied_bytes=copied, memcpy=dict(
                       address=hex(base+checked['memcpy']), n=TARGET_LEN))
    else:
        if 'HOSTILE_CHECKED_MEMCPY' not in text:
            raise SystemExit('%s did not reach encbound_memcpy: %s' %
                             (label, result['log']))
        if 'HOSTILE_CHECKED_ABORT' not in text:
            raise SystemExit('%s did not reach encbound_abort: %s' %
                             (label, result['log']))
        source = dump_bytes(text.split('HOSTILE_CHECKED_MEMCPY', 1)[1]
                                .split('HOSTILE_CHECKED_ABORT', 1)[0])
        check_dump(source, label+' source')
        required = ['encbound_abort (code=3)', 'encbound_require',
                    'encbound_memcpy', TARGET, 'HOSTILE_ABORT_CODE=3',
                    'Program received signal SIGILL']
        if not all(item in text for item in required):
            missing = [item for item in required if item not in text]
            raise SystemExit('%s protected attribution missing %s: %s' %
                             (label, missing, result['log']))
        if not re.search(r'width=(?:width@entry=)?32\b', text):
            raise SystemExit('%s width attribution missing: %s' %
                             (label, result['log']))
        if not re.search(r'kind=(?:kind@entry=)?1\b', text):
            raise SystemExit('%s read-kind attribution missing: %s' %
                             (label, result['log']))
        provider = ('raw_data_provider::process' if mode == 'raw'
                    else 'sealed_data_provider')
        if provider not in text:
            raise SystemExit('%s provider frame missing: %s' %
                             (label, result['log']))
        if 'YEEZ HOSTILE SURVIVED' in text:
            raise SystemExit('%s protected row survived: %s' %
                             (label, result['log']))
        row = dict(outcome='rejected-before-copy', abort='encbound-policy',
                   abort_code=3, access='read', width=TARGET_LEN,
                   source_bytes=source,
                   memcpy=dict(address=hex(base+checked['encbound_memcpy']),
                               n=TARGET_LEN))
    excerpt = [line for line in text.splitlines()
               if any(item in line for item in
                      ('HOSTILE_', 'encbound_', 'raw_data_provider::process',
                       'sealed_data_provider', 'Program received signal',
                       'captured', 'aad_mac_text'))
               or line.startswith(('0x', '#0 ', '#1 ', '#2 ', '#3 '))]
    row.update(script=str(script), log=result['log'],
               log_sha256=sha(result['log']), excerpt=excerpt)
    return row, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--evidence', type=Path, default=None)
    parser.add_argument('--rebuild', action='store_true',
                        help='resign/recompile the selected signed images')
    parser.add_argument('--config', action='append', default=None,
                        help='limit to PROFILE-low|PROFILE-high (repeatable)')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    selected = set(args.config or [])
    rows = []
    for profile, high in CONFIGS:
        label = profile+'-'+('high' if high else 'low')
        if selected and label not in selected:
            continue
        build = build_record(profile)
        signed, dest = signed_record(profile, high, out, args.rebuild)
        image = Path(signed['signed']['analyzer']['image'])
        unsigned = Path(build['images']['analyzer']['image'])
        base = int(signed['signed']['analyzer']['base'], 16)
        target_info = target(unsigned, base)
        checked = symbols(unsigned, profile)
        print(label, 'target', hex(target_info['pointer']),
              target_info['section'], flush=True)
        for mode in ('raw', 'sealed'):
            row, _ = trace(dest, label+'-'+mode, dest/'host', image,
                           Path(signed['signed']['keymgr']['image']), base,
                           target_info, profile, mode, checked)
            row.update(profile=profile, high=high, mode=mode, base=hex(base),
                       target=target_info,
                       unsigned={kind: build['images'][kind]['sha256']
                                 for kind in ('analyzer', 'keymgr')},
                       signed={kind: signed['signed'][kind]['sha256']
                               for kind in ('analyzer', 'keymgr')},
                       host_sha256=sha(dest/'host'))
            rows.append(row)
            print(label, mode, row['outcome'], flush=True)
    record = dict(date='2026-10-24',
                  scope='original YeeZ analyzer public path; hostile host next_data_batch pointer into analyzer protected application data; native SDK SIM only',
                  target=dict(symbol=TARGET, length=TARGET_LEN,
                              expected_bytes=list(EXPECTED)),
                  rows=rows)
    if not rows:
        raise SystemExit('no configurations selected')
    (out/'results.json').write_text(json.dumps(record, indent=2)+'\n')
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(record, indent=2)+'\n')
    print('wrote', rel(out/'results.json'))


if __name__ == '__main__':
    main()
