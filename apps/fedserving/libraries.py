#!/usr/bin/env python3
"""Build the combiner's private formatter and eight additional math C units."""
import os
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('--build', type=Path, required=True)
p.add_argument('--profile', required=True)
a = p.parse_args()
b = a.build.resolve()
overlay = b/'core-headers'
sdk = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
subprocess.run(['python3', ROOT/'tools/prepare_cxx_headers.py', '--sdk', sdk, '--out', overlay], check=True)
flags = ['-I'+str(b/'generated'), '-I'+str(b/'prepared'), '-I'+str(overlay)]
subprocess.run(['python3', ROOT/'apps/libc-format/build.py', '--profile', a.profile,
                '--out-dir', b/'libc-format', '--extra-pins', HERE/'libc-pins.json',
                '--caller', b/'prepared/Enclave.cpp',
                *['--caller-flag='+f for f in flags]], check=True)
r = json.loads((b/'libc-format/build.json').read_text())
names = (b/'libc-format/admitted.txt').read_text()
names += (b/'generated/admitted-ocalls.txt').read_text()
names += (b/'generated/admitted-app.txt').read_text()
(b/'admitted.txt').write_text(names)
(b/'library-objects.txt').write_text(' '.join(r['objects'])+'\n')
