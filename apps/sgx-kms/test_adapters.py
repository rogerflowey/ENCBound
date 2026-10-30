#!/usr/bin/env python3
"""Native service-contract tests: SDK spies plus real runtime, no SGX/crypto."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
BUILD = ROOT/'build/sgx-kms/adapter-native'
BUILD.mkdir(parents=True, exist_ok=True)
rows = []
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
inputs = [HERE/'adapters_test.c', HERE/'adapters.c', ROOT/'tests/fake_platform.c',
          *[ROOT/f'runtime/{n}.c' for n in ('siphash','runtime','capability','allocations','allocator','adapters')]]
for profile in ('RADIX_ONLY','MAC27'):
    for opt in ('-O0','-O2'):
        name = profile+opt
        exe = BUILD/name
        command = ['gcc', '-g', opt, '-Wall', '-Wextra', '-Wno-unused-parameter', '-Werror', '-DENCBOUND_PROTECTED',
                   *(['-DENCBOUND_MAC27'] if profile == 'MAC27' else []),
                   *['-I'+str(p) for p in (ROOT/'include',ROOT/'runtime',ROOT/'tests',SDK/'include')],
                   *map(str,[v for v in inputs if v != HERE/'adapters.c']), '-o', str(exe)]
        result = subprocess.run(command,capture_output=True,text=True)
        (BUILD/(name+'-build.log')).write_text(result.stdout+result.stderr)
        assert not result.returncode, result.stderr
        result = subprocess.run([exe],capture_output=True,text=True)
        (BUILD/(name+'-run.log')).write_text(result.stdout+result.stderr)
        assert not result.returncode, (name,result.stdout,result.stderr)
        assert 'SGX-KMS ADAPTER NATIVE PASS' in result.stdout
        rows.append(dict(profile=profile,opt=opt,result='pass',output=result.stdout,command=command,
                         image_sha256=sha(exe)))
        print(name, result.stdout.strip())
(BUILD/'results.json').write_text(json.dumps(dict(scope='native SDK spies; no SGX or crypto result',
    rows=rows,inputs={str(p):sha(p) for p in [*inputs,Path(__file__)]}),indent=2)+'\n')
