#!/usr/bin/env python3
"""Fresh full-interface and isolated-declaration diagnostics; no SQL execution."""
import os
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SDK=Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))

def run(build):
    b=build.resolve();out=b/'feasibility';out.mkdir(exist_ok=True)
    source=b/'upstream/isv_enclave'
    text=(source/'isv_enclave.edl').read_text()
    interface={'records':{'Condition':{'header':'definitions.h'},'Schema':{'header':'definitions.h'}},'sdk_only_imports':{}}
    imported=SDK/'include/sgx_tkey_exchange.edl'
    interface['sdk_only_imports']['sgx_tkey_exchange.edl']=dict(
        domain='sdk',sha256=hashlib.sha256(imported.read_bytes()).hexdigest(),
        symbols=['sgx_ra_get_ga','sgx_ra_proc_msg2_trusted','sgx_ra_get_msg3_trusted'],
        reason='Diagnostic generation only. Pinned SDK-owned trusted RA entries retain stock ABI; no raw application service admission.')
    (out/'interface.json').write_text(json.dumps(interface,indent=2)+'\n')
    (out/'isolated-interface.json').write_text(json.dumps(dict(records=interface['records'],sdk_only_imports={}),indent=2)+'\n')
    inputs={'original':source/'isv_enclave.edl'}
    for name in ('opOneLinearScanBlock','createTable','rowMatchesCondition','getTableSchema'):
        decl=re.search(r'public \w+ '+name+r'\([^;]*?\);',text).group()
        edl=out/(name+'.edl')
        edl.write_text('enclave { include "definitions.h"\ntrusted {\n'+decl+'\n}; };\n')
        inputs[name]=edl
    rows=[]
    for profile in ('BASELINE','RADIX_ONLY','MAC27'):
        for name,edl in inputs.items():
            target=out/(name+'-'+profile)
            command=['python3',ROOT/'tools/modified_bridge.py','--edl',edl,
                     '--interface',out/('interface.json' if name=='original' else 'isolated-interface.json'),'--generator',ROOT/'build/edger8r/sgx_edger8r',
                     '--out-dir',target,'--profile',profile,'--cc','cc','--layout-cc','clang-21',
                     '--search-path',source,'--search-path',SDK/'include',
                     '--cflag=-I'+str(source),'--cflag=-I'+str(SDK/'include'),
                     '--cflag=-I'+str(SDK/'include/tlibc'),'--cflag=-nostdinc']
            result=subprocess.run(list(map(str,command)),capture_output=True,text=True)
            log=out/(name+'-'+profile+'.log');log.write_text(result.stdout+result.stderr)
            rows.append(dict(name=name,profile=profile,mode='native EDL generation only',
                             command=list(map(str,command)),returncode=result.returncode,
                             edl_sha256=hashlib.sha256(edl.read_bytes()).hexdigest(),
                             log=str(log),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                             diagnostic=(result.stdout+result.stderr).strip()))
    for row in rows:
        assert (row['returncode']==0)==(row['name'] in ('opOneLinearScanBlock','createTable')),row
    record=dict(rows=rows,claims=dict(full_application=False,SQL_execution=False),
                source_revision=json.loads((HERE/'pins.json').read_text())['revision'])
    (out/'results.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True)
    print(json.dumps(run(p.parse_args().build),indent=2))
