#!/usr/bin/env python3
"""Fresh hostile-shape controls for the selected ConFlow softmax ECALLs.

The upstream softmax and softmax_grad bodies allocate enclave scratch from N
but index it as M rows of C elements. Passing N < M*C crosses the protected
allocation; a negative C with M>1 makes i*C negative and reads before it. The
input/gradient host arrays are complete in both cases. This is an application
memory-safety bug, not an ENCBound mechanism change.

The script records four separate controls:
  * unchanged native body under AddressSanitizer (independent OOB proof);
  * the same body under the real checked runtime on the fake platform;
  * the original SDK SIM ECALLs in BASELINE/RADIX_ONLY/MAC27/high-base MAC27;
  * debugger attribution of the checked abort.
"""
import argparse
import hashlib
import json
import os
import resource
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SDK = Path(os.environ.get('SGX_SDK',
    str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
CONFIGS = [('BASELINE', '0x40000000'), ('RADIX_ONLY', '0x40000000'),
           ('MAC27', '0x40000000'), ('MAC27', '0x140000000')]
MODES = ['softmax-valid', 'softmax-shape', 'softmax-shape-large',
         'softmax-negative-c', 'softmax-grad-valid', 'softmax-grad-shape',
         'softmax-grad-negative-c']
NEGATIVE_MODES = ('softmax-negative-c', 'softmax-grad-negative-c')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def clean_env(**updates):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith('ENCBOUND_')}
    env.update(updates)
    return env


def build_dir(profile, base):
    suffix = '' if base == '0x40000000' else '-base' + base[2:]
    return ROOT / 'build/conflow' / ('SIM-' + profile +
        '-feO2-cgO2-rtO2-fused' + suffix)


def write_log(dest, name, text):
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / (name + '.log')
    path.write_text(text)
    return str(path)


def run(dest, name, command, env=None, timeout=180):
    proc = subprocess.run([str(x) for x in command], capture_output=True,
                          text=True, env=env, timeout=timeout)
    log = write_log(dest, name, proc.stdout + proc.stderr)
    return dict(command=[str(x) for x in command], returncode=proc.returncode,
                log=log, stdout=proc.stdout, stderr=proc.stderr)


def prepare_builds(dest):
    env = clean_env()
    rows = []
    for profile, base in CONFIGS:
        b = build_dir(profile, base)
        b.mkdir(parents=True, exist_ok=True)
        proc = run(dest, 'build-' + profile + '-' + base[2:],
                   ['make', '-C', HERE, '-j4', 'PROFILE=' + profile,
                    'ENCLAVE_BASE=' + base, 'SGX_SDK=' + str(SDK), 'all', 'vuln-host'],
                   env=env, timeout=1800)
        if proc['returncode']:
            raise SystemExit('build failed: ' + proc['log'])
        rows.append(dict(profile=profile, base=base, build=str(b),
                         log=proc['log']))
    return rows


def sim_rows(dest):
    rows = []
    for profile, base in CONFIGS:
        b = build_dir(profile, base)
        env = dict(os.environ, ENCBOUND_TEST_BASE=base,
                   LD_LIBRARY_PATH=str(SDK / 'sdk_libs') + ':' +
                                  str(SDK / 'lib64'))
        row = dict(profile=profile, base=base, modes={})
        for mode in MODES:
            name = profile + ('-' + base[2:] if base != '0x40000000' else '') + '-' + mode
            r = run(dest, name, [b / 'host/vuln-host',
                                 b / 'enclave/enclave.signed.so', mode], env=env)
            expected = 0
            if mode in NEGATIVE_MODES:
                if profile in ('RADIX_ONLY', 'MAC27'):
                    expected = -4      # SIGILL from __builtin_trap
            elif mode in ('softmax-shape', 'softmax-shape-large',
                          'softmax-grad-shape'):
                if profile == 'MAC27':
                    expected = -4      # SIGILL from __builtin_trap
                elif profile == 'BASELINE':
                    expected = -11     # SIGSEGV after heap corruption
            if r['returncode'] != expected:
                raise SystemExit('%s %s expected rc=%d got %d: %s' %
                                 (profile, base, expected, r['returncode'],
                                  r['log']))
            row['modes'][mode] = {k: r[k] for k in
                                  ('command', 'returncode', 'log')}
        rows.append(row)
    return rows


def functional_rows():
    rows = []
    for profile, base in CONFIGS:
        b = build_dir(profile, base)
        env = dict(os.environ, ENCBOUND_TEST_BASE=base,
                   LD_LIBRARY_PATH=str(SDK / 'sdk_libs') + ':' +
                                  str(SDK / 'lib64'))
        proc = subprocess.run([str(b / 'host/host'),
                               str(b / 'enclave/enclave.signed.so')],
                              capture_output=True, text=True, env=env,
                              timeout=60)
        if proc.returncode:
            raise SystemExit('functional host failed: %s %s\n%s' %
                             (profile, base, proc.stderr))
        rows.append(dict(profile=profile, base=base,
                         returncode=proc.returncode,
                         functional=json.loads(proc.stdout.strip()
                                               .splitlines()[-1])))
    return rows


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def write_evidence(path, res, functional):
    sim = []
    for row in res['sim']:
        modes = {m: dict(returncode=v['returncode'], log=rel(v['log']),
                         log_sha256=sha(v['log']))
                 for m, v in row['modes'].items()}
        sim.append(dict(profile=row['profile'], base=row['base'], modes=modes))
    gdb = [dict(profile=r['profile'], base=r['base'], mode=r['mode'],
                abort_code=r['abort_code'], source_line=r['source_line'],
                excerpt=r['excerpt'], log=rel(r['log']),
                log_sha256=sha(r['log']))
           for r in res['gdb']]
    asan = []
    for r in res['asan']:
        lines = Path(r['log']).read_text().splitlines()
        asan.append(dict(mode=r['mode'], returncode=r['returncode'],
                         log=rel(r['log']), log_sha256=sha(r['log']),
                         first_lines=lines[:10]))
    native = [dict(profile=r['profile'],
                   modes={k: dict(expected=v['expected'],
                                  returncode=v['returncode'],
                                  output=v['output'], log=rel(v['log']))
                          for k, v in r['modes'].items()})
              for r in res['native']]
    record = dict(
        date=datetime.now().astimezone().date().isoformat(),
        application='conflow-dev/ConFlow selected operators',
        observed_at=datetime.now(timezone.utc).isoformat(),
        scope='SDK SIM plus native controls; no hardware or exploit claim',
        pins=json.loads((ROOT / 'evidence/2026-10-21-conflow.json')
                        .read_text())['pins'],
        sharing=dict(Ne=5, Nt=6, insert=4, indexs=[1, 2, 0, 3, 1, 0]),
        finding=res['finding'], functional_recheck=functional,
        functional_recheck_note='Fresh run of the unchanged functional host '
            'after the Makefile/source additions; the application and prepared '
            'bodies were unchanged.',
        sim=sim, gdb_attribution=gdb, asan=asan, native_checked=native,
        inputs=res['inputs'], artifacts=res['artifacts'], limits=res['limits'])
    Path(path).write_text(json.dumps(record, indent=2) + '\n')
    return record


def gdb_rows(dest):
    rows = []
    for profile, base in CONFIGS:
        if profile != 'MAC27':
            continue
        b = build_dir(profile, base)
        env = dict(os.environ, ENCBOUND_TEST_BASE=base,
                   LD_LIBRARY_PATH=str(SDK / 'sdk_libs') + ':' +
                                  str(SDK / 'lib64'))
        for mode, symbol, code, line in (
                ('softmax-shape', 'ecall_softmax', 5, 'Enclave.cpp:359'),
                ('softmax-grad-shape', 'ecall_softmax_grad', 5,
                 'Enclave.cpp:436'),
                ('softmax-negative-c', 'ecall_softmax', 3,
                 'Enclave.cpp:357'),
                ('softmax-grad-negative-c', 'ecall_softmax_grad', 3,
                 'Enclave.cpp:434')):
            script = dest / ('attr-' + base[2:] + '-' + mode + '.gdb')
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text('set pagination off\nset confirm off\n'
                'break conflow_trace_ready\nrun\n'
                'add-symbol-file %s -o %s\ncontinue\nbt 12\n' %
                (b / 'enclave/enclave.so', base))
            r = run(dest, 'attr-' + base[2:] + '-' + mode,
                    ['gdb', '-q', '-batch', '-x', script, '--args',
                     b / 'host/vuln-host', b / 'enclave/enclave.signed.so', mode],
                    env=env)
            text = r['stdout'] + r['stderr']
            need = ['encbound_abort (code=%d)' % code, 'encbound_require',
                    symbol, line]
            missing = [n for n in need if n not in text]
            if missing:
                raise SystemExit('attribution missing %s: %s' %
                                 (missing, r['log']))
            rows.append(dict(profile=profile, base=base, mode=mode,
                             symbol=symbol, abort_code=code,
                             source_line=line, script=str(script),
                             log=r['log'], excerpt=[
                                 l for l in text.splitlines()
                                 if any(n in l for n in need)]))
    return rows


ASAN_MAIN = r'''
extern "C" unsigned sgx_read_rand(unsigned char *p, size_t n) {
    return getrandom(p, n, 0) == (ssize_t)n ? 0 : 1;
}
int main(int argc, char **argv) {
    float in[320], grad[320], out[514] = {0};
    const char *mode = argc > 1 ? argv[1] : "softmax";
    for (int i = 0; i < 320; ++i) {
        in[i] = (float)((i % 17) - 8) * 0.125f;
        grad[i] = (float)((i % 13) - 6) * 0.25f;
    }
    if (!strcmp(mode, "grad"))
        ecall_softmax_grad(in, grad, 4, 1, 5, out);
    else if (!strcmp(mode, "neg"))
        ecall_softmax(in, 4, 2, -1, out);
    else if (!strcmp(mode, "neg-grad"))
        ecall_softmax_grad(in, grad, 4, 2, -1, out);
    else
        ecall_softmax(in, 4, 1, 5, out);
    printf("ACCEPTED %g\n", out[0]);
    return 0;
}
'''

DECLS = '''
extern "C" void ecall_softmax(float *, int, int, int, float *);
extern "C" void ecall_softmax_grad(float *, float *, int, int, int, float *);
'''


def asan_control(dest, prepared):
    text = prepared.read_text()
    text = text.replace('#include "Enclave_t.h"',
                        '#include <stdio.h>\n#include <string.h>\n'
                        '#include <sys/random.h>')
    text = text.replace('#include "sgx_trts.h"',
                        'extern "C" unsigned sgx_read_rand(unsigned char *, size_t);')
    text = text.replace('extern "C" unsigned sgx_read_rand(unsigned char *, size_t);',
                        'extern "C" unsigned sgx_read_rand(unsigned char *, size_t);' + DECLS)
    src = dest / 'asan.cpp'
    src.write_text(text + ASAN_MAIN)
    binary = dest / 'asan'
    compile_cmd = ['clang++-21', '-std=c++17', '-O1', '-g', '-fno-builtin',
                   '-fsanitize=address', '-fno-omit-frame-pointer',
                   src, '-o', binary]
    c = run(dest, 'asan-compile', compile_cmd)
    if c['returncode']:
        raise SystemExit('ASan compile failed: ' + c['log'])
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1')
    rows = []
    for mode in ('softmax', 'grad', 'neg', 'neg-grad'):
        r = run(dest, 'asan-' + mode, [binary, mode], env=env)
        text = r['stdout'] + r['stderr']
        symbol = ('ecall_softmax' if mode in ('softmax', 'neg')
                  else 'ecall_softmax_grad')
        need = ['AddressSanitizer: heap-buffer-overflow', 'READ of size 4',
                symbol]
        missing = [n for n in need if n not in text]
        if r['returncode'] == 0 or missing:
            raise SystemExit('ASan %s did not report the OOB: %s (%s)' %
                             (mode, missing, r['log']))
        rows.append(dict(mode=mode, returncode=r['returncode'], log=r['log'],
                         sha256=sha(src),
                         compile=[str(x) for x in compile_cmd]))
    return rows, src


def native_control(dest, prepared):
    text = prepared.read_text()
    text = text.replace('#include "Enclave_t.h"', '#include <stddef.h>')
    text = text.replace('#include "sgx_trts.h"',
                        'extern "C" unsigned sgx_read_rand(unsigned char *, size_t);')
    text = text.replace('extern "C" unsigned sgx_read_rand(unsigned char *, size_t);',
                        'extern "C" unsigned sgx_read_rand(unsigned char *, size_t);' + DECLS)
    app = dest / 'native-app.cpp'
    app.write_text(text)
    admitted = dest / 'admitted.txt'
    admitted.write_text('sgx_read_rand\nexpf\nsqrtf\nlogf\nfmaxf\nfabs\n')

    driver = dest / 'driver.o'
    c = run(dest, 'native-driver', ['clang++-21', '-O2', '-g',
             '-I' + str(ROOT / 'include'), '-I' + str(ROOT / 'runtime'),
             '-I' + str(ROOT / 'tests'), '-c',
             HERE / 'vuln_native_driver.cpp', '-o', driver])
    if c['returncode']:
        raise SystemExit('native driver compile failed: ' + c['log'])

    c_sources = [ROOT / 'tests/fake_platform.c'] + [
        ROOT / 'runtime' / (n + '.c') for n in
        ('check_core', 'allocator', 'allocations', 'adapters')]
    rows = []
    for profile in ('RADIX_ONLY', 'MAC27'):
        flag = ['-DENCBOUND_MAC27'] if profile == 'MAC27' else []
        objects = []
        for source in c_sources:
            obj = dest / (profile + '-' + source.stem + '.o')
            c = run(dest, 'native-' + profile + '-' + source.stem,
                    ['clang-21', '-O2', '-g', *flag,
                     '-I' + str(ROOT / 'include'), '-I' + str(ROOT / 'runtime'),
                     '-I' + str(ROOT / 'tests'), '-c', source, '-o', obj])
            if c['returncode']:
                raise SystemExit('native runtime compile failed: ' + c['log'])
            objects.append(obj)
        app_obj = dest / ('native-app-' + profile + '.o')
        env = clean_env(
            ENCBOUND_PROFILE=profile, ENCBOUND_CODEGEN_OPT='-O2',
            ENCBOUND_CXX_ALLOCATIONS='1', ENCBOUND_CALLBACKS='0',
            ENCBOUND_AGGREGATE_ABI='0', ENCBOUND_ATOMICS='0',
            ENCBOUND_VIRTUALS='0', ENCBOUND_VARIADICS='0',
            ENCBOUND_PROTECTED_GLOBALS='0', ENCBOUND_CXX_LIFECYCLE='0',
            ENCBOUND_VLA='0', ENCBOUND_CXX_EH='0', ENCBOUND_CHECK_REUSE='off',
            ENCBOUND_LOCAL_PROOFS='0', ENCBOUND_FAST_PATHS='off',
            ENCBOUND_KEEP_GEP_FLAGS='0', ENCBOUND_POST_INSTCOMBINE='0',
            ENCBOUND_ADMITTED=str(admitted))
        c = run(dest, 'native-app-' + profile,
                [ROOT / 'tools/encbound-cc.sh', app, app_obj, '-x', 'c++',
                 '-std=c++17', '-fno-exceptions', '-fno-rtti', '-fno-builtin',
                 '-O2', '-g', '-Xclang', '-disable-O0-optnone'], env=env)
        if c['returncode']:
            raise SystemExit('native app compile failed: ' + c['log'])
        binary = dest / ('native-' + profile)
        c = run(dest, 'native-link-' + profile,
                ['clang++-21', '-O2', '-g', driver, app_obj, *objects,
                 '-o', binary, '-lm'])
        if c['returncode']:
            raise SystemExit('native link failed: ' + c['log'])
        row = dict(profile=profile, binary=str(binary), modes={})
        for op in ('softmax', 'softmax_grad'):
            for label, dims, expected in (
                    ('valid', ('4', '1', '4'), 'ACCEPTED'),
                    ('shape', ('4', '1', '5'),
                     'ABORT code=5' if profile == 'MAC27' else 'ACCEPTED')):
                r = run(dest, 'native-%s-%s-%s' % (profile, op, label),
                        [binary, op, *dims])
                text = r['stdout'] + r['stderr']
                if expected not in text:
                    raise SystemExit('native %s %s %s expected %s: %s' %
                                     (profile, op, label, expected, r['log']))
                row['modes'][op + '-' + label] = dict(
                    expected=expected, returncode=r['returncode'],
                    output=text.strip(), log=r['log'])
        rows.append(row)
    return rows, app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path,
                        default=ROOT / 'build/conflow/vuln/results.json')
    parser.add_argument('--evidence', type=Path, default=None,
                        help='optionally write the curated checked-in record')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    dest = args.out.parent
    dest.mkdir(parents=True, exist_ok=True)

    builds = [] if args.skip_build else prepare_builds(dest)
    sim = sim_rows(dest)
    gdb = gdb_rows(dest)
    prepared = build_dir('MAC27', '0x40000000') / 'prepared/Enclave.cpp'
    asan, asan_src = asan_control(dest, prepared)
    native, native_src = native_control(dest, prepared)

    result = dict(
        application='conflow-dev/ConFlow selected operators',
        scope='SDK SIM plus native controls; no hardware or exploit claim',
        finding=dict(
            kind='application heap out-of-bounds access (CWE-787/CWE-125)',
            ecalls=['ecall_softmax', 'ecall_softmax_grad'],
            conditions=[
                'host-supplied N < M*C: index past the scratch allocation',
                'host-supplied negative C with M>1: negative index before the '
                'scratch allocation (for example N=4,M=2,C=-1)'],
            affected_upstream_lines=dict(
                ecall_softmax=dict(positive=2213, negative=2211),
                ecall_softmax_grad=dict(positive=2290, negative=2288)),
            note='scratch is allocated from N and indexed as M rows of C; '
                 'no validation ties N, M and C together or rejects signed '
                 'negative dimensions'),
        builds=builds, sim=sim, gdb=gdb, asan=asan, native=native,
        inputs={str(p): sha(p) for p in
                (HERE / 'vuln.py', HERE / 'vuln_host.c',
                 HERE / 'vuln_native_driver.cpp', HERE / 'Makefile',
                 HERE / 'prepare.py', HERE / 'pins.json')},
        artifacts=dict(asan_source=str(asan_src),
                       asan_source_sha256=sha(asan_src),
                       native_source=str(native_src),
                       native_source_sha256=sha(native_src),
                       prepared=str(prepared),
                       prepared_sha256=sha(prepared),
                       upstream=str(ROOT / 'build/conflow/source/sgx_tf_ops/Enclave/Enclave.cpp'),
                       upstream_sha256=sha(ROOT / 'build/conflow/source/sgx_tf_ops/Enclave/Enclave.cpp')),
        limits=[
            'The complete input and gradient arrays are passed; only N, M and C disagree.',
            'The selected positive case N=4,C=5 crosses a 16-byte protected '
            'slot. Smaller sub-slot overruns can remain in slot padding.',
            'The negative-C case reads before the 16-byte allocation and is '
            'rejected as POLICY because the preceding slot base is outside the '
            'protected heap region in these runs; that category can depend on '
            'allocation placement.',
            'RADIX_ONLY accepts the positive same-radix adjacent-slot access '
            'but rejects the negative underflow; MAC27 authenticates the slot '
            'and rejects both. This is the existing authentication contrast, '
            'not a new mechanism.',
            'BASELINE dies with SIGSEGV on the positive shape after heap '
            'corruption; the negative-C shape returns success after a silent '
            'out-of-bounds read. Native ASan independently identifies both '
            'out-of-object accesses.',
            'No hardware, exploit, information-leak, TensorFlow/DeepCrossing or '
            'full-ConFlow claim is made.',
        ])
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print('WROTE', args.out)
    if args.evidence:
        write_evidence(args.evidence, result, functional_rows())
        print('WROTE', args.evidence)


if __name__ == '__main__':
    main()
