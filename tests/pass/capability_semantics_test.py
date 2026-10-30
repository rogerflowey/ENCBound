#!/usr/bin/env python3
"""C0/C1/C2/C3 focused fixtures for the capability-semantics correction.

docs/legacy/steps/04a-capability-semantics.md and docs/legacy/steps/10-evaluation-campaign.md E0:

  * C1: scalar GEPs are retained without address/no-wrap promises; executed
    constant/dynamic/negative/struct/nested/padded forms match independent
    expected 64-bit representation results.
  * C2: unjustified function/parameter/call promises are removed, ABI attributes
    are preserved, and `llvm.assume` is dropped.
  * C3: `encbound-verify` rejects output that removes a check, uses the wrong
    width or kind, retains an unjustified GEP flag, or lets a decoded pointer escape.

These are representation/transform fixtures. They do not claim that invalid C
pointer expressions are defined, and they are not enclave execution evidence.
"""
from pathlib import Path
import ctypes
import os
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / 'build/pass/encbound_pass.so'
OUT = ROOT / 'build/pass/semantics'
OUT.mkdir(parents=True, exist_ok=True)

HEADER = ('target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-'
          'i64:64-i128:128-f80:128-n8:16:32:64-S128"\n'
          'target triple = "x86_64-pc-linux-gnu"\n')
REQ = 'declare i64 @encbound_require(i64, i64, i32)\n'

failures = []


def check(name, condition, detail=''):
    if condition:
        print(f'  ok: {name}')
    else:
        failures.append(f'{name}: {detail}')
        print(f'  FAIL: {name}: {detail}')


def write_ir(name, body, header=True):
    path = OUT / f'{name}.ll'
    path.write_text((HEADER if header else '') + body)
    # Establish that a rejection is ours, not malformed input.
    subprocess.run(['opt-21', '-passes=verify', '-disable-output', str(path)],
                   check=True)
    return path


def transform(name, body):
    src = write_ir(name, body)
    dst = OUT / f'{name}.inst.ll'
    result = subprocess.run(
        ['opt-21', '-load-pass-plugin=' + str(PLUGIN),
         '-passes=encbound,encbound-verify,verify', '-S', str(src), '-o', str(dst)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (OUT / f'{name}.log').write_text(result.stderr)
    if result.returncode != 0:
        sys.exit(f'FAIL: {name}: admitted fixture rejected\n{result.stderr}')
    return dst.read_text()


def verify_only(name, body):
    src = write_ir(name, body)
    return subprocess.run(
        ['opt-21', '-load-pass-plugin=' + str(PLUGIN),
         '-passes=encbound-verify,verify', '-disable-output', str(src)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def expect_reject(name, body):
    result = verify_only(name, body)
    (OUT / f'{name}.log').write_text(result.stderr)
    check(name, result.returncode != 0, 'validator accepted invalid output')
    check(f'{name} diagnostic',
          'ENCBound: validation failed' in result.stderr,
          result.stderr.strip()[:200])


def expect_accept(name, body):
    result = verify_only(name, body)
    (OUT / f'{name}.log').write_text(result.stderr)
    check(name, result.returncode == 0, f'validator rejected valid output: '
          f'{result.stderr.strip()[:200]}')


def expect_transform_reject(name, body, needle):
    src = write_ir(name, body)
    dst = OUT / f'{name}.inst.ll'
    result = subprocess.run(
        ['opt-21', '-load-pass-plugin=' + str(PLUGIN),
         '-passes=encbound,encbound-verify,verify', '-S', str(src), '-o', str(dst)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (OUT / f'{name}.log').write_text(result.stderr)
    check(name, result.returncode != 0, 'transform accepted an unsupported form')
    check(f'{name} diagnostic', needle in result.stderr,
          result.stderr.strip()[:200])


def function_attr_text(text, fname):
    """The define line plus any numbered attribute groups it references, so a
    removed function attribute cannot hide in an `attributes #N = { ... }` line."""
    lines = text.splitlines()
    sig = next((l for l in lines
                if l.startswith('define') and f'@{fname}(' in l), '')
    groups = set(re.findall(r'#(\d+)', sig))
    extra = [l for l in lines
             if l.startswith('attributes #') and l.split()[1].lstrip('#') in groups]
    return '\n'.join([sig] + extra)


print('== C1: retained GEP bit results ==')
S_TYPES = '%struct.S = type { i8, i32, [3 x i16], i64 }\n'
CASES = [
    # (name, extra types, function body, expected add operand, extra regex)
    ('gep_struct_field', S_TYPES,
     'define ptr @f(ptr %base) {\n'
     '  %p = getelementptr inbounds %struct.S, ptr %base, i64 0, i32 2, i64 1\n'
     '  ret ptr %p\n'
     '}\n', '10', None),
    ('gep_padded_struct', '%padded = type { i8, i64 }\n',
     'define ptr @f(ptr %base) {\n'
     '  %p = getelementptr inbounds %padded, ptr %base, i64 0, i32 1\n'
     '  ret ptr %p\n'
     '}\n', '8', None),
    ('gep_negative', '',
     'define ptr @f(ptr %base) {\n'
     '  %p = getelementptr inbounds i64, ptr %base, i64 -1\n'
     '  ret ptr %p\n'
     '}\n', '-8', None),
    ('gep_nested_array', '%arr = type [3 x [4 x i32]]\n',
     'define ptr @f(ptr %base) {\n'
     '  %p = getelementptr inbounds %arr, ptr %base, i64 1, i64 2\n'
     '  ret ptr %p\n'
     '}\n', '80', None),
    ('gep_dynamic_index', '',
     'define ptr @f(ptr %base, i64 %i) {\n'
     '  %p = getelementptr inbounds i32, ptr %base, i64 %i\n'
     '  ret ptr %p\n'
     '}\n', None, None),
]
for name, types, body, operand, extra in CASES:
    text = transform(name, types + body)
    check(f'{name} retained getelementptr', 'getelementptr' in text,
          'executable GEP was replaced')
    check(f'{name} no inbounds', 'inbounds' not in text, 'inbounds promise survived')
    lib = OUT / f'{name}.so'
    subprocess.run(['clang-21', '-shared', '-fPIC', '-O2', '-Xclang',
                    '-disable-llvm-passes', str(OUT / f'{name}.inst.ll'),
                    '-o', str(lib)], check=True)
    f = ctypes.CDLL(str(lib)).f
    f.restype = ctypes.c_void_p
    f.argtypes = [ctypes.c_void_p] + ([ctypes.c_int64] if operand is None else [])
    bits_ok = True
    for base in [0, 0x0801234500001000, 0xf0123456fffffff8, (1 << 64)-1]:
        for index in [0, 1, -1, 17, -(1 << 63), (1 << 63)-1]:
            args = [base] + ([index] if operand is None else [])
            offset = int(operand) if operand is not None else index * 4
            bits_ok &= (f(*args) or 0) == ((base + offset) & ((1 << 64)-1))
    check(f'{name} executed bit results', bits_ok, 'unexpected byte offset or tag loss')

print('== C1: allocation-origin lowering (alloca and malloc) ==')
alloc_body = (S_TYPES +
              'define void @f(i64 %v) {\n'
              '  %a = alloca %struct.S, align 8\n'
              '  %p = getelementptr inbounds %struct.S, ptr %a, i64 0, i32 3\n'
              '  store i64 %v, ptr %p\n'
              '  ret void\n'
              '}\n')
text = transform('gep_alloca_origin', alloc_body)
check('alloca origin minted', 'encbound_stack_mint' in text, 'no stack mint')
check('alloca origin retained gep', 'getelementptr' in text, 'GEP replaced')
check('alloca origin checked store', 'encbound_require' in text, 'store unchecked')

malloc_body = (S_TYPES +
               'declare ptr @malloc(i64)\n'
               'define void @f(i64 %v) {\n'
               '  %b = call ptr @malloc(i64 32)\n'
               '  %p = getelementptr inbounds %struct.S, ptr %b, i64 0, i32 3\n'
               '  store i64 %v, ptr %p\n'
               '  ret void\n'
               '}\n')
text = transform('gep_malloc_origin', malloc_body)
check('malloc origin redirected', 'encbound_malloc' in text, 'not redirected')
check('malloc origin no raw malloc call', 'call ptr @malloc' not in text,
      'raw malloc call survived')
check('malloc origin retained gep', 'getelementptr' in text, 'GEP replaced')
check('malloc origin checked store', 'encbound_require' in text, 'store unchecked')

print('== C2: attribute reconciliation ==')
attr_body = (
    'declare ptr @malloc(i64) allocsize(0) mustprogress\n'
    'define i32 @pure(i32 %x) readnone willreturn mustprogress nofree nosync {\n'
    '  ret i32 %x\n'
    '}\n'
    'define zeroext i32 @abi(i8 signext %x) {\n'
    '  %r = zext i8 %x to i32\n'
    '  ret i32 %r\n'
    '}\n'
    'define void @dropped(ptr nonnull dereferenceable(8) align 8 %p) {\n'
    '  call void @llvm.assume(i1 true)\n'
    '  ret void\n'
    '}\n'
    'define void @alloc(i64 %n) {\n'
    '  %p = call ptr @malloc(i64 %n)\n'
    '  ret void\n'
    '}\n')
text = transform('attributes', attr_body)
pure_attrs = function_attr_text(text, 'pure')
for attr in ['readnone', 'willreturn', 'mustprogress', 'nofree', 'nosync']:
    check(f'removed {attr}', attr not in pure_attrs,
          f'{attr} survived on @pure (signature or attribute group)')
for attr in ['nonnull', 'dereferenceable', 'align 8']:
    check(f'removed param {attr}', attr not in text, f'{attr} survived')
check('preserved zeroext', 'zeroext' in text, 'ABI return attr dropped')
check('preserved signext', 'signext' in text, 'ABI param attr dropped')
check('assume call removed', 'call void @llvm.assume' not in text,
      'llvm.assume call survived')
check('allocsize removed',
      'allocsize' not in text, 'allocsize survived after declaration sanitize')

print('== C2: loaded-pointer metadata removal ==')
meta_body = (
    'define ptr @meta(ptr %p) {\n'
    '  %v = load ptr, ptr %p, align 8, !nonnull !0, !dereferenceable !1\n'
    '  ret ptr %v\n'
    '}\n'
    '!0 = !{}\n'
    '!1 = !{i64 8}\n')
meta_text = transform('metadata', meta_body)
for md in ['!nonnull', '!dereferenceable', '!range', '!invariant.load',
           '!noalias', '!alias.scope']:
    check(f'metadata {md} stripped', md not in meta_text, f'{md} survived')
check('metadata load checked', 'encbound_require' in meta_text,
      'load without metadata was left unchecked')

print('== C2: unsupported implicit-memory ABI rejected ==')
expect_transform_reject('abi_sret',
                        'define void @f(ptr sret(i64) %out) {\n  ret void\n}\n',
                        'unsupported argument ABI')
expect_transform_reject('abi_byref',
                        'define void @f(ptr byref(i64) %p) {\n  ret void\n}\n',
                        'unsupported argument ABI')
expect_transform_reject('abi_sret_callsite', REQ +
                        'declare void @g(ptr sret(i64))\n'
                        'define void @f(ptr %out) {\n'
                        '  call void @g(ptr sret(i64) %out)\n'
                        '  ret void\n'
                        '}\n',
                        'implicit memory argument ABI')

print('== C3: validator negatives ==')
REQ = 'declare i64 @encbound_require(i64, i64, i32)\n'
expect_reject('val_unchecked_load',
              'define i64 @f(ptr %p) {\n  %v = load i64, ptr %p\n  ret i64 %v\n}\n')
expect_reject('val_unchecked_store',
              'define void @f(ptr %p) {\n  store i64 0, ptr %p\n  ret void\n}\n')
expect_accept('val_plain_gep',
              'define ptr @f(ptr %p) {\n  %q = getelementptr i8, ptr %p, i64 1\n  ret ptr %q\n}\n')
for flags in ['inbounds', 'nuw', 'nusw']:
    expect_reject('val_gep_' + flags,
                  'define ptr @f(ptr %p) {\n  %q = getelementptr ' + flags +
                  ' i8, ptr %p, i64 1\n  ret ptr %q\n}\n')
expect_reject('val_wrong_width', REQ +
              'define i64 @f(ptr %p) {\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 4, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  %v = load i64, ptr %q\n'
              '  ret i64 %v\n'
              '}\n')
expect_reject('val_wrong_kind', REQ +
              'define void @f(ptr %p) {\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 8, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  store i64 0, ptr %q\n'
              '  ret void\n'
              '}\n')
expect_reject('val_escaped_decoded', REQ +
              'define ptr @f(ptr %p) {\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 8, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  %v = load i64, ptr %q\n'
              '  ret ptr %q\n'
              '}\n')
expect_reject('val_unchecked_memcpy',
              'declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1)\n'
              'define void @f(ptr %d, ptr %s) {\n'
              '  call void @llvm.memcpy.p0.p0.i64(ptr %d, ptr %s, i64 8, i1 false)\n'
              '  ret void\n'
              '}\n')
expect_reject('val_bad_dominance', REQ +
              'define i1 @f(ptr %p, i1 %c) {\n'
              'entry:\n'
              '  br i1 %c, label %check, label %use\n'
              'check:\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 8, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  br label %use\n'
              'use:\n'
              '  %d = phi ptr [ %p, %entry ], [ %q, %check ]\n'
              '  %v = load i64, ptr %d\n'
              '  ret i1 true\n'
              '}\n')
expect_accept('val_accept_direct', REQ +
              'define i64 @f(ptr %p) {\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 8, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  %v = load i64, ptr %q\n'
              '  ret i64 %v\n'
              '}\n')
expect_accept('val_accept_zero_memset',
              'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n'
              'define void @f(ptr %p) {\n'
              '  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 0, i1 false)\n'
              '  ret void\n'
              '}\n')

print('== C3/R2: guarded memory-intrinsic PHI proof ==')
# Positive: exactly the instrumenter's emitted guarded form.
expect_accept('val_accept_guarded_memset', REQ +
              'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n'
              'define void @f(ptr %p, i64 %n) {\n'
              'entry:\n'
              '  %z = icmp ne i64 %n, 0\n'
              '  br i1 %z, label %check, label %cont\n'
              'check:\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 %n, i32 2)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  br label %cont\n'
              'cont:\n'
              '  %d = phi ptr [ %p, %entry ], [ %q, %check ]\n'
              '  call void @llvm.memset.p0.i64(ptr %d, i8 0, i64 %n, i1 false)\n'
              '  ret void\n'
              '}\n')
# Negative: the unchecked edge is guarded by an unrelated condition, not len==0.
expect_reject('val_mem_unrelated_guard', REQ +
              'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n'
              'define void @f(ptr %p, ptr %q, i1 %unrelated, i64 %n) {\n'
              'entry:\n'
              '  br i1 %unrelated, label %checked, label %merge\n'
              'checked:\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 %n, i32 2)\n'
              '  %q2 = inttoptr i64 %r to ptr\n'
              '  br label %merge\n'
              'merge:\n'
              '  %d = phi ptr [ %q, %entry ], [ %q2, %checked ]\n'
              '  call void @llvm.memset.p0.i64(ptr %d, i8 0, i64 %n, i1 false)\n'
              '  ret void\n'
              '}\n')
# Negative: a second, unguarded unchecked PHI input.
expect_reject('val_mem_extra_unchecked', REQ +
              'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n'
              'define void @f(ptr %p, i1 %first, i64 %n) {\n'
              'entry:\n'
              '  br i1 %first, label %checked, label %evil\n'
              'checked:\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 %n, i32 2)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  br label %merge\n'
              'evil:\n'
              '  br label %merge\n'
              'merge:\n'
              '  %d = phi ptr [ %q, %checked ], [ %p, %evil ]\n'
              '  call void @llvm.memset.p0.i64(ptr %d, i8 0, i64 %n, i1 false)\n'
              '  ret void\n'
              '}\n')
# Negative: the guarded PHI (and thus the decoded pointer) escapes into a return.
expect_reject('val_mem_phi_escape', REQ +
              'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n'
              'define ptr @f(ptr %p, i64 %n) {\n'
              'entry:\n'
              '  %z = icmp eq i64 %n, 0\n'
              '  br i1 %z, label %merge, label %checked\n'
              'checked:\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 %n, i32 2)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  br label %merge\n'
              'merge:\n'
              '  %d = phi ptr [ %p, %entry ], [ %q, %checked ]\n'
              '  call void @llvm.memset.p0.i64(ptr %d, i8 0, i64 %n, i1 false)\n'
              '  ret ptr %d\n'
              '}\n')
# Negative: the raw integer result of the require escapes alongside the load.
expect_reject('val_raw_int_escape', REQ +
              'define i64 @f(ptr %p) {\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 8, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  %v = load i64, ptr %q\n'
              '  ret i64 %r\n'
              '}\n')
# Negative: semantic metadata must not survive into the validated module.
expect_reject('val_semantic_metadata', REQ +
              'define ptr @f(ptr %p) {\n'
              '  %b = ptrtoint ptr %p to i64\n'
              '  %r = call i64 @encbound_require(i64 %b, i64 8, i32 1)\n'
              '  %q = inttoptr i64 %r to ptr\n'
              '  %v = load ptr, ptr %q, !nonnull !0\n'
              '  ret ptr %v\n'
              '}\n'
              '!0 = !{}\n')

print('== Follow-up: intrinsic promises, exact guards, all raw uses ==')
MEMSET = 'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1 immarg)\n'
for length in ['0', '%n']:
    label = 'zero' if length == '0' else 'dynamic'
    body = MEMSET + f'''define void @f(ptr %p, i64 %n) {{
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(16) %p, i8 0, i64 {length}, i1 false)
  ret void
}}
'''
    text = transform('intrinsic_attrs_' + label, body)
    call = next(l for l in text.splitlines() if 'call void @llvm.memset' in l)
    check('intrinsic optional attrs removed ' + label,
          not any(a in call for a in ['noundef', 'nonnull', 'align ', 'dereferenceable']), call)
    check('intrinsic immarg retained ' + label, 'i1 immarg' in text)
    if length == '0':
        check('zero intrinsic has no decode', 'call i64 @encbound_require' not in text)
    expect_reject('val_intrinsic_attrs_' + label, body)

decl_promises = MEMSET.replace('(ptr,', '(ptr nonnull dereferenceable(16),') + '''
define void @f(ptr %p) {
  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 0, i1 false)
  ret void
}
'''
text = transform('intrinsic_declaration_promises', decl_promises)
check('intrinsic declaration promises removed',
      'dereferenceable' not in text and 'nonnull' not in text)
# LLVM 21's reader itself canonicalizes intrinsic declaration attributes; the
# standalone validator therefore sees the safe declaration in this fixture.
expect_accept('val_canonical_intrinsic_declaration', decl_promises)
fn_promises = MEMSET + '''
define void @f(ptr %p) {
  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 0, i1 false) memory(none)
  ret void
}
'''
text = transform('intrinsic_function_promises', fn_promises)
check('intrinsic call function promises removed', 'memory(none)' not in text)
expect_reject('val_intrinsic_function_promises', fn_promises)

expect_reject('val_duplicate_guard_successors', MEMSET + '''
define void @f(ptr %unchecked, i64 %n) {
entry:
  %zero = icmp eq i64 %n, 0
  br i1 %zero, label %join, label %join
join:
  %p = phi ptr [ %unchecked, %entry ], [ %unchecked, %entry ]
  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 %n, i1 false)
  ret void
}
''')
expect_reject('val_dynamic_intrinsic_direct_decode', REQ + MEMSET + '''
define void @f(i64 %cap, i64 %n) {
  %raw = call i64 @encbound_require(i64 %cap, i64 %n, i32 2)
  %p = inttoptr i64 %raw to ptr
  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 %n, i1 false)
  ret void
}
''')
expect_reject('val_decode_on_zero_phi_arm', REQ + MEMSET + '''
define void @f(i64 %cap, i64 %n) {
entry:
  %unrelated_raw = call i64 @encbound_require(i64 %cap, i64 8, i32 2)
  %zero_ptr = inttoptr i64 %unrelated_raw to ptr
  %zero = icmp eq i64 %n, 0
  br i1 %zero, label %join, label %checked
checked:
  %raw = call i64 @encbound_require(i64 %cap, i64 %n, i32 2)
  %p = inttoptr i64 %raw to ptr
  br label %join
join:
  %q = phi ptr [ %zero_ptr, %entry ], [ %p, %checked ]
  call void @llvm.memset.p0.i64(ptr %q, i8 0, i64 %n, i1 false)
  ret void
}
''')
expect_reject('val_orphan_raw_integer', REQ + '''
define i64 @f(i64 %cap) {
  %raw = call i64 @encbound_require(i64 %cap, i64 8, i32 1)
  ret i64 %raw
}
''')
expect_reject('val_orphan_raw_pointer', REQ + '''
define ptr @f(i64 %cap) {
  %raw = call i64 @encbound_require(i64 %cap, i64 8, i32 1)
  %p = inttoptr i64 %raw to ptr
  ret ptr %p
}
''')
expect_reject('val_store_raw_into_itself', REQ + '''
define void @f(i64 %cap) {
  %raw = call i64 @encbound_require(i64 %cap, i64 8, i32 2)
  %p = inttoptr i64 %raw to ptr
  store ptr %p, ptr %p
  ret void
}
''')
expect_reject('val_unused_raw_result', REQ + '''
define void @f(i64 %cap) {
  %raw = call i64 @encbound_require(i64 %cap, i64 8, i32 2)
  ret void
}
''')
expect_reject('val_zero_intrinsic_decodes', REQ + MEMSET + '''
define void @f(i64 %cap) {
  %raw = call i64 @encbound_require(i64 %cap, i64 1, i32 2)
  %p = inttoptr i64 %raw to ptr
  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 0, i1 false)
  ret void
}
''')
for abi in ['sret', 'byref']:
    expect_reject('val_abi_definition_' + abi,
                  f'define void @f(ptr {abi}(i64) %p) {{ ret void }}\n')
    expect_reject('val_abi_declaration_' + abi,
                  f'declare void @f(ptr {abi}(i64))\n')

print('== C4/E0.2: machine code has check-before-access ==')
c_src = OUT / 'check_before_access.c'
c_src.write_text(
    'unsigned long probe(unsigned long base, unsigned long value) {\n'
    '    unsigned long *p = (unsigned long *)base;\n'
    '    *p = value;\n'
    '    return *p;\n'
    '}\n')
obj = OUT / 'check_before_access.o'
env = {**os.environ, 'ENCBOUND_PROFILE': 'MAC27'}
driver = subprocess.run([str(ROOT / 'tools/encbound-cc.sh'), str(c_src), str(obj),
                         '-O1'], text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env=env)
(OUT / 'check_before_access.driver.log').write_text(driver.stdout + driver.stderr)
check('driver emitted object', driver.returncode == 0 and obj.is_file(),
      driver.stderr.strip()[:200])
disasm = subprocess.run(['objdump', '-dr', str(obj)], text=True,
                        stdout=subprocess.PIPE).stdout
(OUT / 'check_before_access.objdump.txt').write_text(disasm)
call_idx = disasm.find('encbound_require')
check('call to encbound_require', call_idx != -1, 'no check call in machine code')
if call_idx != -1:
    after = disasm[call_idx:]
    saved = re.search(r'mov\s+%rax,%?(r[a-z0-9]+)', after)
    check('returned address saved', saved is not None,
          'check return did not reach a register')
    if saved:
        reg = '%' + saved.group(1)
        store = re.search(r'mov\s+[^,]+,\(' + re.escape(reg) + r'\)', after)
        check('store uses returned address', store is not None,
              f'no store through {reg} after the call')

if failures:
    print(f'\nCAPABILITY SEMANTICS FAIL ({len(failures)}):')
    for f in failures:
        print(' -', f)
    sys.exit(1)
print('\nCAPABILITY SEMANTICS PASS')
