#!/usr/bin/env python3
"""Fetch pinned upstream and extract the exact selected operator bodies."""
import argparse
import hashlib
import io
import json
import re
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE/'pins.json').read_text())
FUNCTIONS = ['gaussrand_NORMAL', 'gaussrand', 'ecall_encrypt', 'ecall_decrypt',
             'ecall_relu', 'ecall_sigmoid', 'ecall_relu_grad', 'ecall_sigmoid_grad',
             'ecall_softmax', 'ecall_softmax_grad']


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def function(text, name):
    matches = list(re.finditer(r'^(?:void|float) '+re.escape(name)+r'\([^\n]*\)\s*\{', text, re.M))
    assert len(matches) == 1, name
    start = matches[0].start()
    pos = text.index('{', start)
    depth = 1
    end = pos+1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    src, out = a.source.resolve(), a.out.resolve()
    if not (src/'sgx_tf_ops/Enclave/Enclave.cpp').exists():
        data = urllib.request.urlopen(PINS['archive_url'], timeout=60).read()
        assert hashlib.sha256(data).hexdigest() == PINS['archive_sha256'], 'archive drift'
        archive = tarfile.open(fileobj=io.BytesIO(data))
        prefix = archive.getmembers()[0].name+'/'
        for member in archive.getmembers():
            if not member.isfile():
                continue
            rel = Path(member.name.removeprefix(prefix))
            assert not rel.is_absolute() and '..' not in rel.parts
            dest = src/rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(archive.extractfile(member).read())
    for name, expected in PINS['files'].items():
        assert sha(src/name) == expected, 'source drift: '+name
    upstream = (src/'sgx_tf_ops/Enclave/Enclave.cpp').read_text()
    bodies = {n:function(upstream,n) for n in FUNCTIONS}
    headers = '#include "Enclave_t.h"\n#include <stdlib.h>\n#include <string.h>\n#include <math.h>\n#include "sgx_trts.h"\n'
    # An ordinary configuration supported by upstream run.sh: times=5, num=6,
    # key=1,2,0,3,1,0. A key must exclude the final residual slot (insert=4).
    globals_ = 'int indexs[5+5]={1,2,0,3,1,0};\nint insert = 4;\nint Ne = 5;\nint Nt = 6;\n'
    out.mkdir(parents=True, exist_ok=True)
    (out/'Enclave.cpp').write_text(headers+globals_+'\n\n'.join(bodies.values())+'\n')
    edl = (src/'sgx_tf_ops/Enclave/Enclave.edl').read_text()
    declarations = []
    for line in edl.splitlines():
        if any(re.search(r'\b'+n+r'\(', line) for n in FUNCTIONS[2:]):
            declarations.append(line.strip())
    assert len(declarations) == 8
    (out/'Enclave.edl').write_text('enclave {\n from "sgx_tstdc.edl" import *;\n trusted {\n'+
                                  '\n'.join(declarations)+'\n };\n};\n')
    record = dict(repository=PINS['repository'], revision=PINS['revision'], source=str(src),
                  upstream_hashes=PINS['files'],
                  function_hashes={n:hashlib.sha256(b.encode()).hexdigest() for n,b in bodies.items()},
                  prepared_hashes={str(f.relative_to(out.parent)):sha(f)
                                   for f in (out/'Enclave.cpp',out/'Enclave.edl')},
                  adaptations=['extract only ten exact function bodies; omit unreachable functions, data and headers',
                               'run.sh configuration Ne=5,Nt=6,insert=4,indexs={1,2,0,3,1,0}',
                               'select eight original ECALL declarations unchanged, retaining user_check; SDK-only tstdc import'],
                  license=PINS['license'])
    for n, body in bodies.items():
        assert function((out/'Enclave.cpp').read_text(), n) == body
    (out/'prepared.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__ == '__main__':
    main()
