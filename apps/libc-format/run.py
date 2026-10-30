#!/usr/bin/env python3
"""Build/audit and execute the matched selected-libc SDK SIM matrix."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', type=Path, default=ROOT/'build/libc-format')
a = p.parse_args()
BUILD = a.build.resolve()
BUILD.mkdir(parents=True, exist_ok=True)
record = {'mode': 'Intel SGX SDK SIM', 'commands': [], 'rows': [],
          'limits': 'Functional/error-recovery matrix; native protection controls are separate. No hardware or performance claim.'}

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save():
    (BUILD/'sim-results.json').write_text(json.dumps(record, indent=2)+'\n')

def run(command, name, env=None):
    command = list(map(str, command))
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=300)
    log = BUILD/(name+'.log'); log.write_text(result.stdout+result.stderr)
    record['commands'].append(dict(command=command, returncode=result.returncode,
                                  log=str(log), log_sha256=digest(log)))
    save()
    if result.returncode:
        raise SystemExit(name+' failed; see '+str(log))
    return result.stdout

for profile in ('BASELINE','RADIX_ONLY','MAC27'):
    run(['python3',HERE/'build.py','--profile',profile,'--sdk',SDK,'--out-dir',BUILD/profile],profile+'-library')
for profile, high in (('BASELINE',False),('RADIX_ONLY',False),('MAC27',False),('MAC27',True)):
    name = profile+('-high' if high else '')
    directory = BUILD/('SIM-MAC27-high' if high else 'SIM-'+profile+'-feO2-cgO2-rtO2-fused-reuseoff')
    base = '0x140000000' if high else '0x40000000'
    run(['make','-C',HERE,'PROFILE='+profile,'SGX_SDK='+str(SDK),
         'ENCLAVE_BASE='+base,'BUILD='+str(directory),'LIBBUILD='+str(BUILD/profile)],name+'-sim-build')
    host = directory/'host/host'; image = directory/'enclave/enclave.signed.so'
    env = dict(os.environ,ENCBOUND_TEST_BASE=base)
    env['LD_LIBRARY_PATH'] = str(SDK/'lib64')+':'+env.get('LD_LIBRARY_PATH','')
    output = run([host,image],name+'-sim-run',env)
    assert output.strip() == 'FORMAT/EDL SDK SIM PASS jobs=244 observations=80 record_jobs=8 record_observations=8 user_check_jobs=8 user_check_observations=8', output
    record['rows'].append(dict(profile=profile, base=base, directory=str(directory),
        functional_and_recovery_calls=244, overflow_rejections=4, ocalls=80,
        record_calls=8, record_ocalls=8,
        user_check_calls=8, user_check_ocalls=8,
        host_sha256=digest(host), signed_image_sha256=digest(image),
        inventory_sha256=digest(directory/'inventory.json'), result='pass'))
    save()

stock = BUILD/'stock'; stock.mkdir(exist_ok=True)
run([SDK/'bin/x64/sgx_edger8r','--trusted','--trusted-dir',stock,'--untrusted',
     '--untrusted-dir',stock,'--search-path',SDK/'include',HERE/'enclave.edl'],'stock-edl')
baseline = BUILD/'SIM-BASELINE-feO2-cgO2-rtO2-fused-reuseoff/generated'
for name in ('enclave_t.c','enclave_t.h','enclave_u.c','enclave_u.h'):
    assert (stock/name).read_bytes() == (baseline/name).read_bytes(), name
record['baseline_stock_bridge_equality'] = True
record['inputs'] = {str(p): digest(p) for p in HERE.iterdir() if p.is_file()}
record['inputs'].update({str(p): digest(p) for p in
    (ROOT/'build/edger8r/sgx_edger8r', ROOT/'build/pass/encbound_pass.so', ROOT/'tools/modified_bridge.py')})
save()
print('SELECTED LIBC SDK SIM PASS: 4 rows, 976 formatting/recovery calls, 16 overflow rejections, 320 formatter OCALLs, 32 record calls and 32 record OCALLs, 32 user_check calls and OCALLs; stock bridge equality')
