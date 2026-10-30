#!/usr/bin/env python3
"""Materialize pinned, unchanged data-structure units and original ECALL bodies."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE/'pins.json').read_text())

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def function(text, name):
    import re
    match = re.search(r'^\w[^\n]*\b'+name+r'\([^;]*?\)\s*\{', text, re.M)
    assert match, name
    start = match.start()
    opening = text.index('{', match.start())
    depth = 1
    end = opening+1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

def prepare(source, out):
    out.mkdir(parents=True, exist_ok=True)
    upstream = out.parent/'upstream'
    upstream.mkdir(exist_ok=True)
    for name, digest in PINS['files'].items():
        data = subprocess.check_output(['git','-C',str(source),'show',PINS['revision']+':'+name])
        assert hashlib.sha256(data).hexdigest() == digest, name
        target = upstream/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
    for name in ('definitions.h','definitions.cpp','isv_enclave.h','enclave_data_structures.cpp'):
        (out/name).write_bytes((upstream/'isv_enclave'/name).read_bytes())
    # Preserve the upstream printf, including its actual formatting and OCALL.
    bodies = [function((upstream/'isv_enclave/isv_enclave.cpp').read_text(),'printf'),
              function((upstream/'isv_enclave/enclave_tests.cpp').read_text(),'setupPerformanceTest')]
    (out/'workload.cpp').write_text('#include "isv_enclave.h"\n'+ '\n\n'.join(bodies)+'\n')
    (out/'isv_enclave_t.h').write_text('#include "Enclave_t.h"\n')
    edl = (upstream/'isv_enclave/isv_enclave.edl').read_text()
    import re
    ecalls = ['total_init','setupPerformanceTest','opOneLinearScanBlock']
    ocalls = ['ocall_print','ocall_read_block','ocall_write_block','ocall_newStructure','ocall_deleteStructure']
    def declaration(name):
        pattern = r'^\s*(?:public )?\w+ '+name+r'\([^;]*?\);'
        match = re.search(pattern,edl,re.M)
        assert match, name
        return match.group().strip()
    (out/'Enclave.edl').write_text('enclave {\n from "sgx_tstdc.edl" import *;\n include "definitions.h"\n include "sgx_trts.h"\n untrusted {\n'+
        '\n'.join(declaration(n) for n in ocalls)+'\n };\n trusted {\n'+
        '\n'.join(declaration(n) for n in ecalls)+
        '\n public sgx_status_t free_structure(int structureId);\n };\n};\n')
    result = dict(revision=PINS['revision'], upstream_hashes=PINS['files'],
                  source=str(source.resolve()),ecalls=ecalls+['free_structure'],ocalls=ocalls,
                  extracted_bodies={n:hashlib.sha256(s.encode()).hexdigest() for n,s in zip(['printf','setupPerformanceTest'],bodies)},
                  prepared_hashes={str(p.relative_to(out.parent)):sha(p) for p in out.iterdir() if p.is_file() and p.name!='prepared.json'})
    (out/'prepared.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    prepare(a.source,a.out)
