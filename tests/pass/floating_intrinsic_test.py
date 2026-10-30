#!/usr/bin/env python3
"""Check libc-required FP intrinsics against independent IEEE bit operations."""
import ctypes
from pathlib import Path
import resource
import subprocess

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/pass/floating'
OUT.mkdir(parents=True, exist_ok=True)
PLUGIN = ROOT / 'build/pass/encbound_pass.so'
masks = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 240, 1023]
text = 'target triple = "x86_64-pc-linux-gnu"\n'
for width, ty in ((32, 'float'), (64, 'double')):
    text += f'declare {ty} @llvm.copysign.f{width}({ty}, {ty})\n'
    text += f'declare i1 @llvm.is.fpclass.f{width}({ty}, i32 immarg)\n'
    text += f'''define i{width} @copy{width}(i{width} %a, i{width} %b) {{
 %x = bitcast i{width} %a to {ty}
 %y = bitcast i{width} %b to {ty}
 %z = call {ty} @llvm.copysign.f{width}({ty} %x, {ty} %y)
 %r = bitcast {ty} %z to i{width}
 ret i{width} %r
}}
'''
    for mask in masks:
        text += f'''define i32 @class{width}_{mask}(i{width} %a) {{
 %x = bitcast i{width} %a to {ty}
 %b = call i1 @llvm.is.fpclass.f{width}({ty} %x, i32 {mask})
 %r = zext i1 %b to i32
 ret i32 %r
}}
'''
(OUT / 'input.ll').write_text(text)
count = 0
for profile in ('RADIX_ONLY', 'MAC27'):
    checked = OUT / (profile + '.ll')
    subprocess.run(['opt-21', '-load-pass-plugin=' + str(PLUGIN),
                    '-passes=encbound,encbound-verify,verify', '-encbound-profile=' + profile,
                    '-S', OUT / 'input.ll', '-o', checked], check=True)
    assert 'call i64 @encbound_require' not in checked.read_text()
    for opt in ('-O0', '-O2'):
        lib = OUT / (profile + opt + '.so')
        subprocess.run(['clang-21', opt, '-Xclang', '-disable-llvm-passes',
                        '-shared', '-fPIC', checked, '-o', lib], check=True)
        dll = ctypes.CDLL(str(lib))
        for width, fraction, exponent, ctype in ((32, 23, 8, ctypes.c_uint32), (64, 52, 11, ctypes.c_uint64)):
            sign = 1 << (width - 1)
            inf = ((1 << exponent) - 1) << fraction
            # Classify without executing floating arithmetic: signed zeros,
            # subnormals, normals, infinities, quiet/signaling NaNs and payloads.
            samples = [(0, 64), (1, 128), ((1 << fraction) - 1, 128),
                       (1 << fraction, 256), (inf - 1, 256), (inf, 512),
                       (inf | 1, 1), (inf | (1 << (fraction - 1)) | 123, 2)]
            samples += [(bits | sign, {64:32, 128:16, 256:8, 512:4}.get(cls, cls))
                        for bits, cls in samples]
            copy = getattr(dll, 'copy' + str(width))
            copy.argtypes = [ctype, ctype]
            copy.restype = ctype
            for bits, cls in samples:
                for other, _ in samples:
                    assert copy(bits, other) == (bits & (sign - 1)) | (other & sign)
                    count += 1
                for mask in masks:
                    classify = getattr(dll, f'class{width}_{mask}')
                    classify.argtypes = [ctype]
                    classify.restype = ctypes.c_uint32
                    assert classify(bits) == bool(cls & mask), (profile, opt, width, bits, cls, mask)
                    count += 1
# Pointer-sensitive alignment remains outside the admitted value-only subset.
(OUT / 'negative.ll').write_text('''target triple = "x86_64-pc-linux-gnu"
declare ptr @llvm.ptrmask.p0.i64(ptr, i64)
define ptr @f(ptr %p) {
 %q = call ptr @llvm.ptrmask.p0.i64(ptr %p, i64 -16)
 ret ptr %q
}
''')
r = subprocess.run(['opt-21', '-load-pass-plugin=' + str(PLUGIN), '-passes=encbound',
                    '-disable-output', OUT / 'negative.ll'], capture_output=True, text=True)
assert r.returncode and 'ENCBound: unsupported intrinsic' in r.stderr
print(f'FLOATING INTRINSICS PASS: {count} bit-pattern checks; pointer intrinsic rejected')
