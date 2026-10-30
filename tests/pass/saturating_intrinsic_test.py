#!/usr/bin/env python3
"""Admit value-only saturating integer arithmetic; keep rejecting unlisted
intrinsics (E2/LZ4 compiler admission work).

`llvm.usub.sat.v4i32` and its scalar add/sub siblings are pure integer value
operations with no memory, pointer or control-flow effect. They are admitted so
optimized application IR (LZ4 at -O2) can be instrumented; an unlisted value
intrinsic must still be rejected.
"""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
plugin = root / 'build/pass/encbound_pass.so'
out = root / 'build/pass/saturating'
out.mkdir(parents=True, exist_ok=True)
header = (
    'target triple = "x86_64-pc-linux-gnu"\n'
    'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-'
    'i128:128-f80:128-n8:16:32:64-S128"\n'
)
profiles = ('RADIX_ONLY', 'MAC27')

cases = {
    'usub_sat_v4i32': '''declare <4 x i32> @llvm.usub.sat.v4i32(<4 x i32>, <4 x i32>)
define <4 x i32> @f(<4 x i32> %a, <4 x i32> %b) {
  %r = call <4 x i32> @llvm.usub.sat.v4i32(<4 x i32> %a, <4 x i32> %b)
  ret <4 x i32> %r
}''',
    'sadd_sat_i32': '''declare i32 @llvm.sadd.sat.i32(i32, i32)
define i32 @f(i32 %a, i32 %b) {
  %r = call i32 @llvm.sadd.sat.i32(i32 %a, i32 %b)
  ret i32 %r
}''',
    'uadd_sat_i32': '''declare i32 @llvm.uadd.sat.i32(i32, i32)
define i32 @f(i32 %a, i32 %b) {
  %r = call i32 @llvm.uadd.sat.i32(i32 %a, i32 %b)
  ret i32 %r
}''',
    'ssub_sat_i64': '''declare i64 @llvm.ssub.sat.i64(i64, i64)
define i64 @f(i64 %a, i64 %b) {
  %r = call i64 @llvm.ssub.sat.i64(i64 %a, i64 %b)
  ret i64 %r
}''',
}

for name, ir in cases.items():
    path = out / (name + '.ll')
    path.write_text(header + ir + '\n')
    subprocess.run(['opt-21', '-passes=verify', '-disable-output', str(path)],
                   check=True)
    for profile in profiles:
        result = subprocess.run(
            ['opt-21', '-load-pass-plugin=' + str(plugin),
             '-passes=encbound,encbound-verify,verify',
             '-encbound-profile=' + profile, '-S', str(path),
             '-o', str(out / (name + '.' + profile + '.ll'))],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out / (name + '.' + profile + '.log')).write_text(result.stderr)
        if result.returncode != 0 or 'ERROR' in result.stderr:
            sys.exit(f'FAIL: {name}/{profile}: saturating intrinsic rejected\n'
                     f'{result.stderr}')
        checked = (out / (name + '.' + profile + '.ll')).read_text()
        if 'call i64 @encbound_require' in checked:
            sys.exit(f'FAIL: {name}/{profile}: spurious memory check inserted')
    print(f'saturating intrinsic admitted: {name}')

# The negative control: an unlisted value intrinsic is still rejected.
neg = out / 'sqrt_negative.ll'
neg.write_text(header + '''declare double @llvm.sqrt.f64(double)
define double @f(double %x) {
  %r = call double @llvm.sqrt.f64(double %x)
  ret double %r
}
''')
result = subprocess.run(
    ['opt-21', '-load-pass-plugin=' + str(plugin), '-passes=encbound',
     '-encbound-profile=MAC27', '-disable-output', str(neg)],
    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
if result.returncode == 0 or 'ENCBound: unsupported' not in result.stderr:
    sys.exit(f'FAIL: unlisted intrinsic was admitted\n{result.stderr}')
print('unlisted value intrinsic still rejected: llvm.sqrt.f64')
print(f'SATURATING INTRINSIC PASS ({len(cases)} intrinsics x {len(profiles)} '
      f'profiles)')
