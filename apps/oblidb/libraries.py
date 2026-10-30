#!/usr/bin/env python3
"""Build the private C++/formatter/math closure with actual caller inventories."""
import argparse
import json
import shlex
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--build',type=Path,required=True)
p.add_argument('--profile',required=True)
p.add_argument('--sdk',type=Path,required=True)
p.add_argument('--sdk-source',type=Path,required=True)
a=p.parse_args()
b=a.build.resolve()
callers=[b/'prepared'/s for s in ('enclave_data_structures.cpp','definitions.cpp','workload.cpp')]
extra=['-I'+str(b/'prepared'),'-I'+str(b/'generated'),'-Dvsnprintf=app_fmt_vsnprintf',
       '-Dlog=app_fmt_log','-Dlog2=app_fmt_log2','-Dpow=app_fmt_pow',
       '-fno-vectorize','-fno-slp-vectorize']
def run(cmd):
    subprocess.run(list(map(str,cmd)),check=True)
run(['python3',ROOT/'apps/libcxx/prepare.py'])
run(['python3',ROOT/'apps/libcxx/build.py','--profile',a.profile,'--out-dir',b/'libcxx',
     *[x for s in callers for x in ('--caller',s)],*['--caller-flag='+x for x in extra]])
flags=json.loads((b/'libcxx/build.json').read_text())['flags']
run(['python3',ROOT/'apps/libc-format/build.py','--profile',a.profile,'--sdk',a.sdk,
     '--source',a.sdk_source,'--out-dir',b/'libc-format','--extra-pins',HERE/'libc-pins.json',
     '--caller-no-namespace',*[x for s in callers for x in ('--caller',s)],
     *['--caller-flag='+x for x in flags+extra]])
names=''
objects=[]
for lib in ('libcxx','libc-format'):
    record=json.loads((b/lib/'build.json').read_text())
    names+=(b/lib/'admitted.txt').read_text()
    objects+=record['objects']
for n in ('admitted-app.txt','admitted-ocalls.txt'):
    names+=(b/'generated'/n).read_text()
names+='sgx_read_rand = encbound_oblidb_rand\nsgx_rijndael128GCM_encrypt = encbound_oblidb_encrypt\nsgx_rijndael128GCM_decrypt = encbound_oblidb_decrypt\n'
(b/'admitted.txt').write_text(names)
(b/'library-objects.txt').write_text(' '.join(objects)+'\n')
(b/'app-flags.txt').write_text(shlex.join(flags+extra)+'\n')
