#!/usr/bin/env python3
"""C15 boundary-metadata controls on the original YeeZ key-manager ECALLs.

Three variants are run through the original unchanged `generate_ecc_key_pair`,
`sign_message` and `verify_signature` bodies:

  oversized : verify_signature gets pkey_size=128 (fixed 64-byte stack object)
  generate  : generate_ecc_key_pair gets pkey_size=1 (64-byte output)
  sign      : sign_message gets sig_size=1 (65-byte output)

BASELINE should perform the unchecked write and later fault.  RADIX_ONLY and
MAC27 should reject the checked write; the small-output sign variant is recorded
separately because it exercises slot-granularity and MAC27 authentication.
Images come from the audited `build/yeez/full-integration` build.  The driver
only uses public ECALLs and adds no application/EDL/bridge change.
"""
import argparse
import json
import os
import re
import resource
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hostile_control import (ROOT, SDK, build_record, image_limit, rel, run,
                             sha, signed_record, symbol_offset)

BUILD = ROOT/'build/yeez/full-integration'
DEFAULT_OUT = ROOT/'build/yeez/c15-hostile-v1'
CONFIGS = [('BASELINE', False), ('RADIX_ONLY', False),
           ('MAC27', False), ('MAC27', True)]
MODES = ('oversized', 'generate', 'sign')


def call_sites(image, function):
    output = subprocess_output(['objdump', '-d', '-C',
                                '--disassemble='+function, str(image)])
    sites = []
    for line in output.splitlines():
        match = re.match(r'\s*([0-9a-f]+):.*\bcall\b.*<([^>]+)>', line)
        if match:
            sites.append((int(match.group(1), 16), match.group(2)))
    return sites


def subprocess_output(command):
    import subprocess
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def offsets(image):
    values = dict(memcpy=symbol_offset(image, 'memcpy'),
                  memset=symbol_offset(image, 'memset'),
                  abort=symbol_offset(image, 'abort'),
                  serialize=symbol_offset(
                      image, 'secp256k1_ecdsa_recoverable_signature_serialize_compact'),
                  pubkey=symbol_offset(image, 'secp256k1_ec_pubkey_create'))
    if 'encbound_abort' in subprocess_output(['nm', '-C', '--defined-only',
                                              str(image)]):
        values['encbound_abort'] = symbol_offset(image, 'encbound_abort')
    return values


def host_env(base, mode):
    return dict(os.environ,
                LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'),
                YEEZ_MANAGER_BASE=hex(base), YEEZ_C15=mode, YEEZ_VERBOSE='0')


def head(image, base):
    return ('set pagination off\nset confirm off\n'
            'break yeez_c15_ready\nrun\n'
            'add-symbol-file %s -o %#x\n' % (image, base))


def protected_script(image, base, off, mode):
    abort = off['encbound_abort']
    return (head(image, base) +
            'break *(%#x + %#x)\n'
            'commands\n'
            ' silent\n'
            ' printf "C15_ABORT\\n"\n'
            ' bt 12\n'
            ' printf "C15_CODE=%%d\\n", code\n'
            ' continue\n'
            'end\n'
            'continue\n' % (base, abort))


def protected_radix_sign_script(image, base, off):
    return (head(image, base) +
            'break *(%#x + %#x)\n'
            'continue\n'
            'printf "C15_SERIALIZE\\n"\n'
            'printf "C15_CAP=%%p RADIX=%%d\\n", $rsi, (unsigned long)$rsi >> 59\n'
            'set $raw = %#x + ((unsigned long)$rsi & 0xffffffff)\n'
            'printf "C15_RAW=%%p\\n", $raw\n'
            'set $out = $raw\n'
            'finish\n'
            'printf "C15_AFTER_SERIALIZE\\n"\n'
            'x/80bx $out\n'
            'continue\n' % (base, off['serialize'], base))


def baseline_oversized_script(image, base, off):
    return (head(image, base) +
            'break *(%#x + %#x) if $rdx == 128\n'
            'ignore 2 1\n'
            'continue\n'
            'printf "C15_APP_MEMCPY\\n"\n'
            'bt 5\n'
            'x/16bx $rsi\n'
            'set $dst = $rdi\n'
            'finish\n'
            'printf "C15_AFTER_COPY\\n"\n'
            'x/96bx $dst\n'
            'continue\n'
            'printf "C15_STOP\\n"\n'
            'bt 10\n' % (base, off['memcpy']))


def baseline_generate_script(image, base, off):
    sites = call_sites(image, 'secp256k1_ec_pubkey_create')
    calls = [site for site in sites if site[1].endswith('memset')]
    if not calls:
        raise SystemExit('no pubkey memset call site in '+str(image))
    return (head(image, base) +
            'break *(%#x + %#x)\n'
            'continue\n'
            'printf "C15_PUBKEY_MEMSET_CALL\\n"\n'
            'bt 5\n'
            'set $dst = $rdi\n'
            'printf "C15_MEMSET dst=%%p n=%%lu\\n", $dst, $rdx\n'
            'si\n'
            'finish\n'
            'printf "C15_AFTER_MEMSET\\n"\n'
            'x/64bx $dst\n'
            'continue\n'
            'printf "C15_STOP\\n"\n'
            'bt 10\n' % (base, calls[0][0]))


def baseline_sign_script(image, base, off):
    return (head(image, base) +
            'break *(%#x + %#x)\n'
            'continue\n'
            'printf "C15_SERIALIZE\\n"\n'
            'bt 4\n'
            'set $out = $rsi\n'
            'finish\n'
            'printf "C15_AFTER_SERIALIZE\\n"\n'
            'x/80bx $out\n'
            'continue\n'
            'printf "C15_STOP\\n"\n'
            'bt 10\n' % (base, off['serialize']))


def trace(out, label, host, analyzer, keymgr, base, mode, script):
    path = out/(label+'.gdb')
    path.write_text(script)
    result = run(out, label+'-gdb',
                 ['gdb', '-q', '-batch', '-x', str(path), '--args',
                  str(host), str(analyzer), str(keymgr)], host_env(base, mode))
    text = result['stdout']+result['stderr']
    excerpt = [line for line in text.splitlines()
               if any(item in line for item in
                      ('C15_', 'encbound_', 'secp256k1', 'generate_ecc',
                       'sign_message', 'verify_signature', 'Program received',
                       'SIGSEGV', 'SIGILL'))
               or line.startswith(('0x', '#0 ', '#1 ', '#2 ', '#3 ', '#4 '))]
    return result, text, excerpt


def bytes_dump(text, marker, stop=None):
    block = text.split(marker, 1)[1]
    if stop:
        block = block.split(stop, 1)[0]
    return [int(value, 16) for value in
            re.findall(r'0x([0-9a-f]{2})\b',
                       '\n'.join(line for line in block.splitlines()
                                 if re.match(r'^0x[0-9a-f]+(?: <[^>]*>)?:',
                                             line)))]


def row(out, label, profile, high, mode, build, signed, host, analyzer,
        keymgr, base, off):
    if profile == 'BASELINE':
        if mode == 'oversized':
            script = baseline_oversized_script(keymgr, base, off)
        elif mode == 'generate':
            script = baseline_generate_script(keymgr, base, off)
        else:
            script = baseline_sign_script(keymgr, base, off)
        result, text, excerpt = trace(out, label, host, analyzer, keymgr, base,
                                      mode, script)
        if mode == 'oversized':
            if 'C15_APP_MEMCPY' not in text:
                raise SystemExit(label+' did not reach the application memcpy')
            source = bytes_dump(text, 'C15_APP_MEMCPY', 'C15_AFTER_COPY')
            if source[:4] != [0x33, 0x33, 0x33, 0x33]:
                raise SystemExit(label+' unexpected source bytes '+str(source[:8]))
            copied = bytes_dump(text, 'C15_AFTER_COPY', 'C15_STOP')
            if copied[:4] != [0x33, 0x33, 0x33, 0x33]:
                raise SystemExit(label+' unexpected copied bytes '+str(copied[:8]))
            if 'SIGSEGV' not in text:
                raise SystemExit(label+' did not fault after the stack copy')
            source_address = re.search(
                r'(0x[0-9a-f]+):\s+0x33\s+0x33', text.split('C15_APP_MEMCPY', 1)[1])
            stack_address = re.search(
                r'(0x[0-9a-f]+):\s+0x33\s+0x33', text.split('C15_AFTER_COPY', 1)[1])
            detail = dict(application_memcpy=dict(
                n=128,
                source_address=source_address.group(1) if source_address else None,
                destination_address=stack_address.group(1) if stack_address else None,
                destination='fixed 64-byte stack object',
                after_bytes=copied[:96]))
        elif mode == 'generate':
            if 'C15_PUBKEY_MEMSET_CALL' not in text or 'C15_AFTER_MEMSET' not in text:
                raise SystemExit(label+' did not reach the pubkey memset')
            copied = bytes_dump(text, 'C15_AFTER_MEMSET', 'C15_STOP')
            if copied[:64] != [0]*64:
                raise SystemExit(label+' unexpected pubkey bytes')
            if 'SIGSEGV' not in text:
                raise SystemExit(label+' did not fault after the pubkey write')
            address = re.search(r'C15_MEMSET dst=(0x[0-9a-f]+) n=(\d+)', text)
            detail = dict(unchecked_memset=dict(
                n=64, requested_allocation=1,
                destination=address.group(1) if address else None,
                after_bytes=copied[:64]))
        else:
            if 'C15_SERIALIZE' not in text or 'C15_AFTER_SERIALIZE' not in text:
                raise SystemExit(label+' did not reach signature serialization')
            copied = bytes_dump(text, 'C15_AFTER_SERIALIZE', 'C15_STOP')
            if not any(copied[:64]):
                raise SystemExit(label+' signature bytes are all zero')
            if 'SIGSEGV' not in text:
                raise SystemExit(label+' did not fault after the signature write')
            address = re.search(r'output64=(0x[0-9a-f]+)', text)
            detail = dict(unchecked_signature=dict(
                n=65, requested_allocation=1,
                output=address.group(1) if address else None,
                after_bytes=copied[:80]))
        return dict(profile=profile, high=high, mode=mode, base=hex(base),
                    outcome='unchecked-write-then-fault', signal='SIGSEGV',
                    protection='none',
                    detail=detail, script=str(out/(label+'.gdb')),
                    log=result['log'], log_sha256=sha(result['log']),
                    excerpt=excerpt)
    if profile == 'RADIX_ONLY' and mode == 'sign':
        script = protected_radix_sign_script(keymgr, base, off)
        result, text, excerpt = trace(out, label, host, analyzer, keymgr, base,
                                      mode, script)
        if 'C15_SERIALIZE' not in text or 'C15_AFTER_SERIALIZE' not in text:
            raise SystemExit(label+' did not reach signature serialization')
        if 'YEEZ C15 SURVIVED mode=sign' not in text:
            raise SystemExit(label+' did not survive as expected')
        capability = re.search(r'C15_CAP=(0x[0-9a-f]+) RADIX=(\d+)', text)
        if not capability:
            raise SystemExit(label+' missing capability/radix')
        copied = bytes_dump(text, 'C15_AFTER_SERIALIZE')
        return dict(profile=profile, high=high, mode=mode, base=hex(base),
                    outcome='survived-cross-slot-write',
                    capability=capability.group(1),
                    slot_radix=int(capability.group(2)),
                    slot_bytes=1 << int(capability.group(2)),
                    serialized_bytes=64,
                    written_bytes=65,
                    sig64_written_by_caller=True,
                    after_bytes=copied[:80],
                    limitation='RADIX_ONLY admits the original 4-byte '
                               'pointer-arithmetic stores across 16-byte '
                               'protected slots; this is slot-level, not an '
                               'exact 1-byte object bound',
                    script=str(out/(label+'.gdb')), log=result['log'],
                    log_sha256=sha(result['log']), excerpt=excerpt)
    script = protected_script(keymgr, base, off, mode)
    result, text, excerpt = trace(out, label, host, analyzer, keymgr, base,
                                  mode, script)
    if 'C15_ABORT' not in text:
        raise SystemExit(label+' did not reach encbound_abort')
    code = re.search(r'C15_CODE=(\d+)', text)
    if not code:
        raise SystemExit(label+' missing abort code')
    code = int(code.group(1))
    width = re.search(r'width=(?:width@entry=)?(\d+)', text)
    kind = re.search(r'kind=(?:kind@entry=)?(\d+)', text)
    expected = {'oversized': (4, 128, 2, 'encbound_memcpy'),
                'generate': (4, 64, 2, 'encbound_memset'),
                'sign': (5, None, None, 'sign_message')}[mode]
    if code != expected[0]:
        raise SystemExit('%s unexpected abort code %d' % (label, code))
    if expected[1] is not None and (not width or int(width.group(1)) != expected[1]):
        raise SystemExit('%s unexpected width %s' % (label, width and width.group(1)))
    if expected[2] is not None and (not kind or int(kind.group(1)) != expected[2]):
        raise SystemExit('%s unexpected kind %s' % (label, kind and kind.group(1)))
    if expected[3] not in text:
        raise SystemExit('%s missing %s frame' % (label, expected[3]))
    if 'Program received signal SIGILL' not in text:
        raise SystemExit(label+' did not trap after the abort')
    row_value = dict(profile=profile, high=high, mode=mode, base=hex(base),
                     outcome='rejected-before-write', abort_code=code,
                     width=int(width.group(1)) if width else None,
                     kind=int(kind.group(1)) if kind else None,
                     script=str(out/(label+'.gdb')), log=result['log'],
                     log_sha256=sha(result['log']), excerpt=excerpt)
    if mode == 'sign':
        row_value.update(
            access='write',
            limitation='MAC27 rejects with ENCBOUND_ERR_TAG (5) at the first '
                       'cross-slot store; the check is authentication, not an '
                       'exact object-range result')
    else:
        row_value.update(access='write')
    return row_value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--evidence', type=Path, default=None)
    parser.add_argument('--rebuild', action='store_true')
    parser.add_argument('--config', action='append', default=None,
                        help='limit to PROFILE-low|PROFILE-high (repeatable)')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    selected = set(args.config or [])
    rows = []
    for profile, high in CONFIGS:
        label_base = profile+'-'+('high' if high else 'low')
        if selected and label_base not in selected:
            continue
        build = build_record(profile)
        signed, dest = signed_record(profile, high, out, args.rebuild)
        analyzer = Path(signed['signed']['analyzer']['image'])
        keymgr = Path(signed['signed']['keymgr']['image'])
        image = Path(build['images']['keymgr']['image'])
        base = int(signed['signed']['keymgr']['base'], 16)
        off = offsets(image)
        print(label_base, 'base', hex(base), flush=True)
        for mode in MODES:
            label = label_base+'-'+mode
            row_value = row(dest, label, profile, high, mode, build, signed,
                            dest/'host', analyzer, keymgr, base, off)
            row_value.update(
                unsigned=build['images']['keymgr']['sha256'],
                signed=signed['signed']['keymgr']['sha256'],
                host_sha256=sha(dest/'host'),
                keymgr_base=hex(base))
            rows.append(row_value)
            print(label, row_value['outcome'], row_value.get('abort_code', ''),
                  flush=True)
    record = dict(date='2026-10-24',
                  scope='original YeeZ key-manager ECALLs; C15 boundary metadata controls; native SDK SIM only',
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
