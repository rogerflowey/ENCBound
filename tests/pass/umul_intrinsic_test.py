#!/usr/bin/env python3
"""Execute the admitted unsigned multiply-with-overflow intrinsic and reject an unlisted one.

The pass admits llvm.umul.with.overflow because mini-gmp (BotScreen) lowers its
mpn_mul_1 carry check to it. The intrinsic is value-only: it returns the low
product and a 1-bit overflow flag, accepts no pointers and reads no memory, so
the checked IR must carry no encbound_require call. An unlisted value intrinsic
must still be rejected.
"""
import ctypes
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/pass/umul'
OUT.mkdir(parents=True, exist_ok=True)
plugin = ROOT / 'build/pass/encbound_pass.so'
header = 'target triple = "x86_64-pc-linux-gnu"\n'
source = header
for width in [32, 64]:
    t = 'i' + str(width)
    source += f'''declare {{ {t}, i1 }} @llvm.umul.with.overflow.{t}({t}, {t})
define {t} @mul{width}({t} %a, {t} %b) {{
 %ov = call {{ {t}, i1 }} @llvm.umul.with.overflow.{t}({t} %a, {t} %b)
 %of = extractvalue {{ {t}, i1 }} %ov, 1
 %z = zext i1 %of to {t}
 ret {t} %z
}}
'''
(OUT / 'input.ll').write_text(source)
count = 0
for profile in ['RADIX_ONLY', 'MAC27']:
    checked = OUT / (profile + '.ll')
    subprocess.run(['opt-21', '-load-pass-plugin=' + str(plugin),
                    '-passes=encbound,encbound-verify,verify', '-encbound-profile=' + profile,
                    '-S', str(OUT / 'input.ll'), '-o', str(checked)], check=True)
    assert 'call i64 @encbound_require' not in checked.read_text()
    for opt in ['-O0', '-O2']:
        lib = OUT / (profile + opt + '.so')
        subprocess.run(['clang-21', opt, '-Xclang', '-disable-llvm-passes', '-shared', '-fPIC',
                        str(checked), '-o', str(lib)], check=True)
        dll = ctypes.CDLL(str(lib))
        for width, ctype in [(32, ctypes.c_uint32), (64, ctypes.c_uint64)]:
            f = getattr(dll, 'mul' + str(width))
            f.argtypes = [ctype, ctype]
            f.restype = ctype
            mask = (1 << width) - 1
            cases = [(0, 0), (1, 1), (mask, 1), (1, mask), (2, mask), (mask, mask),
                     (1 << (width // 2), 1 << (width // 2))]
            for a, b in cases:
                expected = 1 if (a * b) > mask else 0
                assert f(a, b) == expected, (profile, opt, width, a, b)
                count += 1
(OUT / 'negative.ll').write_text(header + 'declare double @llvm.sqrt.f64(double)\n'
                                 'define double @f(double %x) {\n %v = call double @llvm.sqrt.f64(double %x)\n ret double %v\n}\n')
p = subprocess.run(['opt-21', '-load-pass-plugin=' + str(plugin), '-passes=encbound',
                    '-disable-output', str(OUT / 'negative.ll')], capture_output=True, text=True)
assert p.returncode and 'ENCBound: unsupported' in p.stderr
print(f'UMUL PASS: {count} executions, unknown intrinsic rejection')
