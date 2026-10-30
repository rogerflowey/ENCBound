#!/usr/bin/env python3
"""Reject valid-but-unsupported LLVM IR, with an ENCBound diagnostic."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
plugin = root / 'build/pass/encbound_pass.so'
out = root / 'build/pass/admission'
out.mkdir(parents=True, exist_ok=True)
header = 'target triple = "x86_64-pc-linux-gnu"\n'
cases = {
 'expandload': (root/'tests/fixtures/unchecked-expandload.ll').read_text(),
 'compressstore': '''declare void @llvm.masked.compressstore.v4i32(<4 x i32>, ptr, <4 x i1>)
define void @f(ptr %p, <4 x i32> %v, <4 x i1> %m) {
 call void @llvm.masked.compressstore.v4i32(<4 x i32> %v, ptr %p, <4 x i1> %m)
 ret void
}''',
 'prefetch': '''declare void @llvm.prefetch.p0(ptr, i32, i32, i32)
define void @f(ptr %p) {
 call void @llvm.prefetch.p0(ptr %p, i32 0, i32 3, i32 1)
 ret void
}''',
 'unlisted_value_intrinsic': '''declare double @llvm.sqrt.f64(double)
define double @f(double %x) {
 %r = call double @llvm.sqrt.f64(double %x)
 ret double %r
}''',
 'callbr': '''define void @f() {
 callbr void asm sideeffect "", "!i"() to label %done [label %other]
done:
 ret void
other:
 ret void
}''',
 'va_arg': '''define i32 @f(ptr %p) {
 %v = va_arg ptr %p, i32
 ret i32 %v
}''',
 'fence': '''define void @f() {
 fence seq_cst
 ret void
}''',
 'scalable_load': '''define <vscale x 4 x i32> @f(ptr %p) {
 %v = load <vscale x 4 x i32>, ptr %p
 ret <vscale x 4 x i32> %v
}''',
 'byval': '''declare void @consume(ptr byval(i64))
define void @f(ptr %p) {
 call void @consume(ptr byval(i64) %p)
 ret void
}''',
 'variadic': '''define i32 @f(i32 %v, ...) { ret i32 %v }''',
 'tls_without_function': '@state = thread_local global i32 0',
 'module_asm': 'module asm "nop"\ndefine void @f() { ret void }',
 'oversized_stack': '''define ptr @f() {
 %p = alloca i64, i64 2305843009213693953
 ret ptr %p
}''',
 'address_space': '''define i32 @f(ptr addrspace(1) %p) {
 %v = load i32, ptr addrspace(1) %p
 ret i32 %v
}''',
}
for name, ir in cases.items():
    path = out / (name + '.ll')
    path.write_text(ir if 'target triple' in ir else header + ir + '\n')
    # Establish that a rejection is ours, not a malformed IR fixture.
    subprocess.run(['opt-21', '-passes=verify', '-disable-output', str(path)], check=True)
    result = subprocess.run(['opt-21', '-load-pass-plugin='+str(plugin),
                             '-passes=encbound,verify', '-disable-output', str(path)],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out / (name + '.log')).write_text(result.stderr)
    if result.returncode == 0 or 'ENCBound: unsupported' not in result.stderr:
        sys.exit(f'FAIL: {name}: missing ENCBound admission rejection\n{result.stderr}')
    print(f'admission rejected: {name}')
print(f'ADMISSION PASS ({len(cases)} valid unsupported modules rejected)')
