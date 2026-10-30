#!/usr/bin/env python3
"""Execute admitted integer funnel shifts against independent bit arithmetic."""
import ctypes, random, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/pass/funnel';OUT.mkdir(parents=True,exist_ok=True)
plugin=ROOT/'build/pass/encbound_pass.so'
header='target triple = "x86_64-pc-linux-gnu"\n'
source=header
for op in ['fshl','fshr']:
 for width in [32,64]:
  t='i'+str(width)
  source+=f'''declare {t} @llvm.{op}.{t}({t}, {t}, {t})
define {t} @{op}{width}({t} %a, {t} %b, {t} %s) {{
 %v = call {t} @llvm.{op}.{t}({t} %a, {t} %b, {t} %s)
 ret {t} %v
}}
'''
source+='''declare <4 x i32> @llvm.fshl.v4i32(<4 x i32>, <4 x i32>, <4 x i32>)
define <4 x i32> @vector(<4 x i32> %a, <4 x i32> %b, <4 x i32> %s) {
 %v = call <4 x i32> @llvm.fshl.v4i32(<4 x i32> %a, <4 x i32> %b, <4 x i32> %s)
 ret <4 x i32> %v
}
'''
(OUT/'input.ll').write_text(source)
count=0
for profile in ['RADIX_ONLY','MAC27']:
 checked=OUT/(profile+'.ll')
 subprocess.run(['opt-21','-load-pass-plugin='+str(plugin),'-passes=encbound,encbound-verify,verify','-encbound-profile='+profile,'-S',str(OUT/'input.ll'),'-o',str(checked)],check=True)
 assert 'call i64 @encbound_require' not in checked.read_text()
 for opt in ['-O0','-O2']:
  lib=OUT/(profile+opt+'.so')
  subprocess.run(['clang-21',opt,'-Xclang','-disable-llvm-passes','-shared','-fPIC',str(checked),'-o',str(lib)],check=True)
  dll=ctypes.CDLL(str(lib));rng=random.Random(42)
  for op in ['fshl','fshr']:
   for width,ctype in [(32,ctypes.c_uint32),(64,ctypes.c_uint64)]:
    f=getattr(dll,op+str(width));f.argtypes=[ctype]*3;f.restype=ctype
    mask=(1<<width)-1
    for shift in range(width*2+1):
     for a,b in [(0,mask),(mask,0),(rng.getrandbits(width),rng.getrandbits(width))]:
      s=shift%width;joined=(a<<width)|b
      expected=((joined<<s)>>width)&mask if op=='fshl' else (joined>>s)&mask
      assert f(a,b,shift)==expected,(profile,opt,op,width,a,b,shift)
      count+=1
# Unknown value intrinsic must remain rejected.
(OUT/'negative.ll').write_text(header+'declare double @llvm.sqrt.f64(double)\ndefine double @f(double %x) {\n %v = call double @llvm.sqrt.f64(double %x)\n ret double %v\n}\n')
p=subprocess.run(['opt-21','-load-pass-plugin='+str(plugin),'-passes=encbound','-disable-output',str(OUT/'negative.ll')],capture_output=True,text=True)
assert p.returncode and 'ENCBound: unsupported' in p.stderr
print(f'FUNNEL PASS: {count} scalar executions, vector admission, unknown intrinsic rejection')
