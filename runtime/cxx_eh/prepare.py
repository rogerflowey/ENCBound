#!/usr/bin/env python3
"""Copy exactly pinned SDK ABI headers into a local build; never edit the SDK."""
import os
import argparse
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--source',type=Path)
a=p.parse_args()
pins=json.loads((HERE/'sdk-pins.json').read_text())
source=a.source or Path(os.environ.get('PINNED_SRC', HERE.parents[1]/'deps/intel-sgx'))/'sdk/cpprt/linux'
a.out.mkdir(parents=True,exist_ok=True)
for name,expected in pins['sha256'].items():
    data=(source/name).read_bytes()
    if hashlib.sha256(data).hexdigest()!=expected: raise SystemExit('C++ ABI source pin mismatch: '+name)
    # Retain the reference exception implementation as a review artifact too.
    (a.out/name).write_bytes(data)
(a.out/'pins.json').write_text(json.dumps(pins,indent=2)+'\n')
print(a.out)
