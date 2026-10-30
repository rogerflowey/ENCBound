#!/usr/bin/env python3
"""Automatic x86 variadic packing: native semantics, real checks and ABI closure.

The real runtime executes on the fake platform's alternate machine stack.
This is native evidence, with no SGX simulation/hardware claim.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import resource
import subprocess

R = Path(__file__).resolve().parents[2]
S = R / 'tests/pass'
B = R / 'build/pass/variadics'
B.mkdir(parents=True, exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
commands, rows = [], []


def run(args, name, good=True, env=None):
    args = [str(a) for a in args]
    p = subprocess.run(args, text=True, capture_output=True, env=env)
    (B / (name + '.log')).write_text(p.stdout + p.stderr)
    commands.append(dict(command=args, returncode=p.returncode, log=name + '.log'))
    assert (p.returncode == 0) == good, (name, p.stdout, p.stderr)
    return p


names = ['va_mix', 'va_fp', 'va_many_fixed', 'va_cursors', 'va_promotions',
         'va_recurse', 'va_pointer', 'va_forward', 'va_bad']
admitted = B / 'admitted.txt'
admitted.write_text('\n'.join(names) + '\n')
plugin = R / 'build/pass/encbound_pass.so'
driver = R / 'tools/encbound-cc.sh'
runtime = [R / 'runtime' / (n + '.c') for n in
           ('siphash', 'runtime', 'capability', 'allocator', 'allocations', 'adapters')]
includes = ['-I' + str(R / d) for d in ('include', 'runtime', 'tests')]
oracle = []
for unit in ('readers', 'calls'):
    obj = B / ('oracle-' + unit + '.o')
    run(['clang-21', '-O2', '-DORACLE', '-c', S / ('variadics_' + unit + '.c'), '-o', obj], 'oracle-' + unit)
    oracle.append(obj)

objects = {}
for fe in ('O1', 'O2'):
    for cg in ('O0', 'O2'):
        for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
            name = fe + '-' + cg + '-' + profile
            env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_VARIADICS='1',
                       ENCBOUND_CODEGEN_OPT='-' + cg, ENCBOUND_ADMITTED=str(admitted))
            app = []
            checks = mints = 0
            for unit in ('readers', 'calls'):
                obj = B / (name + '-' + unit + '.o')
                run([driver, S / ('variadics_' + unit + '.c'), obj, '-' + fe], name + '-' + unit, env=env)
                ir = obj.with_suffix('.checked.ll').read_text()
                assert not re.search(r'@llvm\.va_(start|copy|end)', ir)
                assert not re.search(r'^(?:define|declare) .*\.\.\.', ir, re.M)
                assert '__encbound_va_' in ir and '.encbound.abi' in ir
                checks += ir.count('call i64 @encbound_require')
                mints += ir.count('call i64 @encbound_stack_mint')
                record = json.loads(obj.with_suffix('.integration.json').read_text())
                assert record['settings']['ENCBOUND_VARIADICS'] == '1'
                app.append(obj)
            assert (checks > 0 and mints > 0) if profile != 'BASELINE' else checks == mints == 0
            flags = ['-DPROTECTED'] if profile != 'BASELINE' else []
            if profile == 'MAC27': flags += ['-DENCBOUND_MAC27']
            exe = B / name
            run(['clang-21', '-O2', *includes, *flags, S / 'variadics_harness.c',
                 *app, *oracle, R / 'tests/fake_platform.c', *runtime, '-o', exe], name + '-link')
            p = run([exe], name + '-execution')
            assert 'PASS: transformed calls' in p.stdout
            rows.append(dict(case=name, result='pass', checks=checks, stack_mints=mints,
                             terminal_controls=0 if profile == 'BASELINE' else 5 if profile == 'MAC27' else 4))
            objects[name] = app

target = 'target triple = "x86_64-pc-linux-gnu"\ntarget datalayout = "e-p:64:64-i64:64-n8:16:32:64-S128"\n'

# Inlined callers have distinct DISubprogram/inlinedAt chains. The x86 frame
# builder must not reuse the preceding function's debug location for allocas.
debug_src = B / 'debug-inline.c'
debug_src.write_text('''#include <stdarg.h>
int debug_target(int n, ...) {
 va_list ap; va_start(ap,n); int x=va_arg(ap,int); va_end(ap); return x+n;
}
int debug_first(int x) { return debug_target(1,x); }
int debug_second(int x) { return debug_first(x)+debug_first(x+1); }
''')
for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_VARIADICS='1', ENCBOUND_CODEGEN_OPT='-O2')
    run([driver, debug_src, B / ('debug-inline-' + profile + '.o'), '-O2', '-g'],
        'debug-inline-' + profile, env=env)
    rows.append(dict(case='debug-inline-' + profile, result='pass', expected='LLVM verification with debug metadata'))


def reject(name, body, needle, options=(), verify=False, enabled=True):
    src = B / (name + '.ll')
    src.write_text(target + body)
    run(['opt-21', '-passes=verify', '-disable-output', src], name + '-llvm-input')
    cmd = ['opt-21', '-load-pass-plugin=' + str(plugin), '-encbound-profile=MAC27',
           '-passes=encbound-verify' if verify else '-passes=encbound', '-disable-output', src]
    if enabled: cmd += ['-encbound-variadics']
    p = run(cmd + list(options), name, good=False)
    assert needle in p.stderr, (name, p.stderr)
    rows.append(dict(case=name, result='pass', expected='reject', diagnostic=needle))


basic = 'define i64 @f(i32 %n, ...) { ret i64 0 }\n'
reject('default-off', basic, 'unsupported variadic function', enabled=False)
reject('verifier-native-entry', basic, 'native variadic ABI survived', verify=True)
reject('unknown-native-callee', 'declare i64 @printf(i32, ...)\ndefine i64 @g() { %r=call i64 (i32,...) @printf(i32 0,i64 1)\nret i64 %r }', 'unowned variadic declaration')
reject('callback-address', basic + '@fp = global ptr @f\n', 'variadic function address requires callbacks')
reject('indirect-call', 'define i64 @g(ptr %f) { %r=call i64 (i32,...) %f(i32 0,i64 1)\nret i64 %r }', 'indirect variadic call requires callbacks')
reject('wide-int', basic + 'define i64 @g() { %r=call i64 (i32,...) @f(i32 0,i128 1)\nret i64 %r }', 'variadic argument type')
reject('long-double', basic + 'define i64 @g(x86_fp80 %v) { %r=call i64 (i32,...) @f(i32 0,x86_fp80 %v)\nret i64 %r }', 'variadic argument type')
reject('vector', basic + 'define i64 @g(<2 x double> %v) { %r=call i64 (i32,...) @f(i32 0,<2 x double> %v)\nret i64 %r }', 'variadic argument type')
reject('unpromoted-float', basic + 'define i64 @g(float %v) { %r=call i64 (i32,...) @f(i32 0,float %v)\nret i64 %r }', 'variadic argument type')
reject('aggregate-byval', basic + 'define i64 @g(ptr %p) { %r=call i64 (i32,...) @f(i32 0,ptr byval(i64) %p)\nret i64 %r }', 'variadic implicit memory ABI')
reject('hidden-sret', 'define void @f(ptr sret(i64) %p, ...) { ret void }', 'variadic implicit memory ABI')
reject('source-private-name', 'define void @__encbound_va_fake() { ret void }', 'source private variadic ABI')
reject('residual-va-arg', 'define i64 @f(ptr %ap) { %v=va_arg ptr %ap,i64\nret i64 %v }', 'residual LLVM va_arg')
reject('prototype-mismatch', basic + 'define i64 @g() { %r=call i64 (i64,...) @f(i64 0,i64 1)\nret i64 %r }', 'variadic call/ownership/prototype')
reject('inreg', 'define i64 @f(i32 inreg %n, ...) { ret i64 0 }', 'variadic parameter ABI attribute')
reject('musttail', 'define i64 @f(i32 %n, ...) { %v=musttail call i64 (i32,...) @f(i32 %n,...)\nret i64 %v }', 'variadic call/ownership/prototype')
reject('invoke', 'declare i32 @personality()\n' + basic + '''define i64 @g() personality ptr @personality {
 %r=invoke i64 (i32,...) @f(i32 0,i64 1) to label %ok unwind label %error
ok: ret i64 %r
error: %l=landingpad {ptr,i32} cleanup
 resume {ptr,i32} %l
}''', 'variadic call/ownership/prototype', options=['-encbound-admitted-file='+str(admitted)])

# The va_copy expansion uses an i32 intrinsic length against i64 check widths.
# Equal values must validate; changing only the access length must still fail.
copy_ir = objects['O1-O0-MAC27'][0].with_suffix('.checked.ll').read_text()
copy_ir, count = re.subn(r'(call void @llvm\.memcpy\.p0\.p0\.i32\([^\n]*, i32 )24(, i1 false)',
                         r'\g<1>23\2', copy_ir, count=1)
assert count == 1
bad_copy = B / 'short-i32-copy.ll'
bad_copy.write_text(copy_ir)
p = run(['opt-21', '-load-pass-plugin='+str(plugin), '-passes=encbound-verify,verify',
         '-disable-output', bad_copy], 'short-i32-copy', good=False)
assert 'ENCBound: validation failed' in p.stderr
rows.append(dict(case='short-i32-copy', result='pass', expected='verifier rejection'))

# A native library, a different protection profile or a different declaration
# must fail to satisfy the caller's private versioned symbol.
for name, readers in [('wrong-profile', objects['O1-O0-RADIX_ONLY'][0]), ('native-callee', B / 'native-readers.o')]:
    if name == 'native-callee':
        run(['clang-21', '-O1', '-c', S / 'variadics_readers.c', '-o', readers], name + '-compile')
    cmd = ['clang-21', '-O2', *includes, '-DPROTECTED', '-DENCBOUND_MAC27',
           S / 'variadics_harness.c', objects['O1-O0-MAC27'][1], readers, *oracle,
           R / 'tests/fake_platform.c', *runtime, '-o', B / name]
    p = run(cmd, name + '-link', good=False)
    assert '__encbound_va_' in p.stderr and 'undefined reference' in p.stderr
    rows.append(dict(case=name, result='pass', expected='link rejection'))

inputs = [Path(__file__), S / 'variadics_fixture.h', S / 'variadics_readers.c',
          S / 'variadics_calls.c', S / 'variadics_harness.c', plugin,
          R / 'pass/encbound_pass.cpp', R / 'pass/encbound_variadics.h',
          R / 'pass/encbound_x86_variadics.h', R / 'pass/upstream/ExpandVariadics.cpp',
          driver, R / 'tests/fake_platform.c', *runtime]
hashes = {str(p.relative_to(R)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
record = dict(scope='native fake platform, actual alternate machine stack, real runtime; no SDK SIM/hardware',
              compiler=subprocess.check_output(['clang-21', '--version'], text=True).splitlines()[0],
              rows=rows, commands=commands, inputs=hashes,
              artifacts={str(p.relative_to(R)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in B.iterdir() if p.is_file() and p.name != 'results.json'})
(B / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
print('VARIADICS PASS:', len(rows), 'cases, 12 execution rows, 36 terminal protection controls')
