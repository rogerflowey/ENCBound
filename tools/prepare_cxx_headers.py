#!/usr/bin/env python3
"""Create a local, pinned Clang configuration overlay; never modify the SDK."""
import argparse, hashlib, json, tempfile
import os
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--sdk',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
source=a.sdk/'include/libcxx/__config'
original=source.read_bytes()
expected='db09d29bfa05d3f9fe8c02e3bf6159aeca86c530c046f6919a15fd40c5208121'
if hashlib.sha256(original).hexdigest()!=expected: raise SystemExit('SDK libc++ __config pin mismatch')
text=original.decode()
needle='#if defined(_LIBCPP_COMPILER_CLANG)\n'
assert text.count(needle)==1
# Match the SDK GCC configuration, before Clang's no-exceptions and later
# no-RTTI selection. The SDK __sgx header preserves the existing assert policy.
text=text.replace(needle,needle+'\n// ENCBound local Clang port of the SDK configuration entry.\n#include <__sgx>\n')
a.out.mkdir(parents=True,exist_ok=True)
def publish(path, contents):
    if path.exists() and path.read_text() == contents:
        return
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
        f.write(contents)
        temporary = f.name
    os.replace(temporary, path)
publish(a.out/'__config', text)
inputs={str(f.resolve()):hashlib.sha256(f.read_bytes()).hexdigest() for directory in ('libcxx','tlibc','stdc++') for f in sorted((a.sdk/'include'/directory).rglob('*')) if f.is_file()}
publish(a.out/'header-pins.json', json.dumps({'source_config_sha256':expected,'overlay_sha256':hashlib.sha256(text.encode()).hexdigest(),'inputs':inputs},indent=2)+'\n')
print(a.out/'__config')
