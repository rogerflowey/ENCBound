#!/usr/bin/env python3
"""Narrow Juliet call admission: fixed ABI, literal format, fail-closed variants."""
from pathlib import Path
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/pass/juliet-calls'
OUT.mkdir(parents=True, exist_ok=True)
PLUGIN = ROOT / 'build/pass/encbound_pass.so'
HEADER = 'target triple = "x86_64-pc-linux-gnu"\n'
FORMAT = '@fmt = private constant [3 x i8] c"%s\\00"\n'
DECL = 'declare i32 @snprintf(ptr, i64, ptr, ...)\n'
BODY = '''define i32 @app(ptr %dst, i64 %n, ptr %src, ptr %fmt) {
  %r = call i32 (ptr, i64, ptr, ...) @snprintf(ptr %dst, i64 %n, ptr @fmt, ptr %src)
  ret i32 %r
}
'''
VALID = FORMAT + DECL + BODY
cases = {
    'string': (VALID, 'encbound_snprintf_string'),
    'dynamic': (VALID.replace('ptr @fmt, ptr', 'ptr %fmt, ptr'), None),
    'mutable': (VALID.replace('private constant', 'private global'), None),
    'percent_n': (VALID.replace('c"%s', 'c"%n'), None),
    'integer_format': (VALID.replace('c"%s', 'c"%d'), None),
    'prefix': (VALID.replace('[3 x i8] c"%s', '[4 x i8] c"x%s'), None),
    'precision': (VALID.replace('[3 x i8] c"%s', '[5 x i8] c"%.*s'), None),
    'wide': (VALID.replace('[3 x i8] c"%s', '[4 x i8] c"%ls'), None),
    'missing_arg': (VALID.replace(', ptr %src)\n', ')\n'), None),
    'extra_arg': (VALID.replace(', ptr %src)\n', ', ptr %src, i32 7)\n'), None),
    'integer_arg': (VALID.replace(', ptr %src)\n', ', i64 7)\n'), None),
    'wrong_size': (VALID.replace('i64', 'i32'), None),
    'wrong_return': (VALID.replace('i32', 'i64'), None),
    'wrong_callconv': (VALID.replace('declare i32', 'declare win64cc i32')
                      .replace('call i32', 'call win64cc i32'), None),
    'other_varargs': (VALID.replace('@snprintf', '@other_variadic'), None),
    'strncat': ('''declare ptr @strncat(ptr, ptr, i64)
define ptr @app(ptr %dst, ptr %src, i64 %n) {
  %r = call ptr @strncat(ptr %dst, ptr %src, i64 %n)
  ret ptr %r
}
''', 'encbound_strncat'),
}
cases['strncat_wrong_size'] = (cases['strncat'][0].replace('i64', 'i32'), None)

for name, (body, target) in cases.items():
    src = OUT / (name + '.ll')
    src.write_text(HEADER + body)
    # Ensure a negative control is valid LLVM, not just a parser error.
    subprocess.run(['opt-21', '-passes=verify', '-disable-output', src], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for profile in ('RADIX_ONLY', 'MAC27'):
        dest = OUT / f'{name}.{profile}.ll'
        result = subprocess.run(
            ['opt-21', '-load-pass-plugin=' + str(PLUGIN),
             '-passes=encbound,encbound-verify,verify', '-encbound-profile=' + profile,
             '-S', src, '-o', dest], text=True, capture_output=True)
        (OUT / f'{name}.{profile}.log').write_text(result.stderr)
        if target:
            assert result.returncode == 0, (name, profile, result.stderr)
            text = dest.read_text()
            assert re.search(r'call (?:i32|ptr) @' + target + r'\(', text), text
            assert not re.search(r'call .*@(?:snprintf|strncat)\(', text), text
            if target == 'encbound_snprintf_string':
                assert '@encbound_snprintf_string(ptr %dst, i64 %n, ptr @fmt, ptr %src)' in text
                assert 'declare i32 @encbound_snprintf_string(ptr, i64, ptr, ptr)' in text
        else:
            assert result.returncode != 0 and 'ENCBound: unsupported' in result.stderr, (name, result.stderr)

# Exercise the actual compiler driver at both admitted frontend/codegen levels.
source = OUT / 'calls.c'
source.write_text('''#include <stdio.h>
#include <string.h>
int format(char *d, size_t n, const char *s) { return snprintf(d, n, "%s", s); }
char *append(char *d, const char *s, size_t n) { return strncat(d, s, n); }
''')
for profile in ('RADIX_ONLY', 'MAC27'):
    for level in ('-O0', '-O2'):
        obj = OUT / f'calls.{profile}.{level}.o'
        subprocess.run([ROOT / 'tools/encbound-cc.sh', source, obj, level, '-fno-builtin'],
                       env=dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_CODEGEN_OPT=level),
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        undefined = subprocess.check_output(['nm', '-u', obj], text=True)
        assert 'encbound_snprintf_string' in undefined and 'encbound_strncat' in undefined, undefined
        assert not re.search(r' U (snprintf|strncat)$', undefined, re.M), undefined
print(f'JULIET CALL ADMISSION PASS ({len(cases)} IR cases x 2 profiles; 4 driver builds)')
