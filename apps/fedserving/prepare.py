#!/usr/bin/env python3
"""Prepare the pinned combiner; preserve functions and record all adaptations."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE/'pins.json').read_text())

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    src, out = a.source.resolve(), a.out.resolve()
    revision = subprocess.check_output(['git', '-C', src, 'rev-parse', 'HEAD'], text=True).strip()
    assert revision == PINS['revision'], 'source revision drift'
    for name, expected in PINS['files'].items():
        assert sha(src/name) == expected, 'source drift: '+name
    out.mkdir(parents=True, exist_ok=True)
    body = (src/'combiner_sgx/Enclave/Enclave.cpp').read_text()
    old = '\t\tinputs[i].weight = 1;\n\t}\n}'
    assert body.count(old) == 1
    body = body.replace(old, '\t\tinputs[i].weight = 1;\n\t}\n    return 0;\n}')
    (out/'Enclave.cpp').write_text(body)
    header = (src/'combiner_sgx/aggregator.h').read_text()
    assert header.count('#define QUERY_SIZE 7000') == 1
    # A bounded fixture configuration; six models, ten classes and all twenty
    # original update iterations remain. This is not a 7000-query result.
    header = header.replace('#define QUERY_SIZE 7000', '#define QUERY_SIZE 16')
    (out.parent/'aggregator.h').write_text(header)
    edl = (src/'combiner_sgx/Enclave/Enclave.edl').read_text()
    edl = edl.replace('enclave {', 'enclave {\n    from "sgx_tstdc.edl" import *;', 1)
    (out/'Enclave.edl').write_text(edl)
    record = dict(repository=PINS['repository'], revision=revision, source=str(src),
                  upstream_hashes=PINS['files'],
                  prepared_hashes={str(p.relative_to(out.parent)):sha(p) for p in
                                   (out/'Enclave.cpp', out/'Enclave.edl', out.parent/'aggregator.h')},
                  adaptations=['add missing return 0 to int init_model_inputs (ordinary C++ undefined-behavior fix)',
                               'QUERY_SIZE 7000 -> 16 for bounded fixtures; MODEL_NUM=6, CATEGORY_NUM=10, ITERATION_NUM=20 unchanged',
                               'add pinned SDK-only sgx_tstdc.edl import; original public ECALL unchanged'],
                  numerical_limits=['retain inputs[0].weight denominator in cal_output',
                                    'retain final output before the twentieth weight update',
                                    'L2 configuration only; KL integer truncation path untested'])
    (out/'prepared.json').write_text(json.dumps(record, indent=2)+'\n')

if __name__ == '__main__':
    main()
