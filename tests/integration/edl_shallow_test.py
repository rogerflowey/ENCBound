#!/usr/bin/env python3
"""Shallow byte copies and pointer results with real checked application accesses.

Native fake platform, separately instrumented application, no SGX claim.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
FIXTURE = ROOT/'tests/fixtures/shallow_bridge'
OUT = ROOT/'build/integration/edl-shallow'
OUT.mkdir(parents=True, exist_ok=True)
commands, rows = [], []

def run(command, name, env=None):
    command = list(map(str, command))
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    log = OUT/(name+'.log')
    log.write_text(result.stdout+result.stderr)
    commands.append(dict(command=command, returncode=result.returncode, log=str(log),
                         log_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))
    assert result.returncode == 0, log.read_text()
    return result

flags = ['-I'+str(p) for p in (FIXTURE, SDK/'include', ROOT/'include', ROOT/'sdk',
                              ROOT/'runtime', ROOT/'tests', ROOT/'tests/fixtures/modified_bridge')]
for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    dest = OUT/profile
    run(['python3', ROOT/'tools/modified_bridge.py', '--edl', FIXTURE/'shallow.edl',
         '--interface', FIXTURE/'interface.json', '--generator', ROOT/'build/edger8r/sgx_edger8r',
         '--out-dir', dest, '--profile', profile, *['--cflag='+f for f in flags]], profile+'-generate')
    admitted = dest/'admitted.txt'
    admitted.write_text('exercise\n'+(dest/'admitted-ocalls.txt').read_text())
    for opt in ('O0', 'O2'):
        name = profile+'-'+opt
        obj = dest/('application-'+opt+'.o')
        env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted),
                   ENCBOUND_CODEGEN_OPT='-'+opt)
        run([ROOT/'tools/with-integration-defaults.sh', 'env', 'ENCBOUND_CODEGEN_OPT=-'+opt,
             ROOT/'tools/encbound-cc.sh',
             FIXTURE/'application.c', obj, *flags, '-I'+str(dest), '-'+opt, '-fno-builtin'], name+'-application', env)
        definitions = [] if profile == 'BASELINE' else ['-DENCBOUND_PROTECTED']
        if profile == 'MAC27': definitions += ['-DENCBOUND_MAC27']
        runtime = [ROOT/'runtime'/(n+'.c') for n in ('runtime','siphash','capability','allocator','allocations')]
        exe = dest/('test-'+opt)
        run(['clang-21', '-O1', *definitions, *flags, '-I'+str(dest), FIXTURE/'harness.c', obj,
             ROOT/'tests/fake_platform.c', ROOT/'sdk/boundary_support.c', *runtime, '-o', exe], name+'-link')
        result = run([exe], name+'-execute')
        rows.append(dict(profile=profile, optimization=opt, result='pass', output=result.stdout.strip(),
                         executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
stock = OUT/'stock'
stock.mkdir(exist_ok=True)
run([SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock, '--untrusted',
     '--untrusted-dir', stock, FIXTURE/'shallow.edl'], 'stock')
for suffix in ('_t.c','_t.h','_u.c','_u.h'):
    assert (stock/('shallow'+suffix)).read_bytes() == (OUT/'BASELINE'/('shallow'+suffix)).read_bytes()
(OUT/'results.json').write_text(json.dumps(dict(scope=__doc__, rows=rows, commands=commands,
                                               baseline_matches_stock=True), indent=2)+'\n')
print('SHALLOW EDL PASS:', len(rows), 'native O0/O2 rows; flexible/opaque/shallow copies, pointer transport/results, access controls, stock equality')
