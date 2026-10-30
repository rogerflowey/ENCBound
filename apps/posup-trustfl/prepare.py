#!/usr/bin/env python3
"""Prepare pinned, explicitly bounded POSUP and TrustFL ECALL closures."""
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCES = ROOT/'build/paper-sources'
PINS = {
    'POSUP': dict(repository='thanghoang/POSUP', revision='9a6e181763535fd927bca1749cd804e5d77f2f73', license='MIT'),
    'TrustFL': dict(repository='zeyu-zh/TrustFL', revision='9e05a7e160bbf4fa1e7a426767f69158ea89b22d', license='Apache-2.0'),
}
FUNCTIONS = {'POSUP': ['ecall_getPathID', 'ecall_setFileIDs'],
             'TrustFL': ['ecall_init', 'ecall_data_preprocess']}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def function(text, name):
    # All four pinned definitions have simple, single-line signatures and
    # balanced braces in comments. This is extraction, not a C++ parser.
    matches = list(re.finditer(r'^(?:void|int) '+re.escape(name)+r'\([^\n]*\)[^{]*\{', text, re.M))
    assert len(matches) == 1, name
    start = matches[0].start()
    end = text.index('{', start)+1
    depth = 1
    while depth:
        depth += (text[end] == '{')-(text[end] == '}')
        end += 1
    return text[start:end]


def prepare(app, out, checkout=None):
    pin = PINS[app]
    checkout = checkout or SOURCES/app
    paths = ['Enclave', 'LICENSE', 'Makefile', 'include' if app == 'POSUP' else 'Include']
    data = subprocess.check_output(['git', '-C', str(checkout), 'archive', pin['revision'], *paths])
    source = out/'source'
    source.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            rel = Path(member.name)
            assert not rel.is_absolute() and '..' not in rel.parts
            if member.isdir():
                (source/rel).mkdir(parents=True, exist_ok=True)
            else:
                assert member.isfile(), 'unexpected source member '+member.name
                target = source/rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
    original = source/('Enclave/Enclave.cpp' if app == 'POSUP' else 'Enclave/verify.cpp')
    bodies = {name: function(original.read_text(), name) for name in FUNCTIONS[app]}
    prepared = out/'prepared'
    prepared.mkdir()
    header = '#include "Enclave_t.h"\n#include <stdlib.h>\n#include <string.h>\n'
    if app == 'POSUP':
        header += '#include <set>\n'
        globals_ = '\n'.join(line for line in (source/'Enclave/Enclave.h').read_text().splitlines()
                             if line in ('std::set<TYPE_ID> lst_fid;', 'std::set<TYPE_ID>::iterator iter_lst_fid;', 'TYPE_ID pathID;'))+'\n'
        assert len(globals_.splitlines()) == 3
        # Test-only observation: expose the selected application-owned set to
        # an ordinary copied EDL buffer. No SDK/runtime state or minting API.
        diagnostic = '''
int diagnostic_fileids(int *output, int capacity) {
    int i = 0;
    for (int value : lst_fid) { if (i < capacity) output[i] = value; ++i; }
    return i;
}
'''
        (prepared/'types.h').write_text('typedef int TYPE_ID;\n')
        decls = [line.strip() for line in (source/'Enclave/Enclave.edl').read_text().splitlines()
                 if any(re.search(r'\b'+n+r'\(', line) for n in FUNCTIONS[app])]
        decls += ['public int diagnostic_fileids([out, count=capacity] int *output, int capacity);']
        includes = ' include "types.h"\n'
    else:
        header += '#include <stdint.h>\n#include <sgx_tcrypto.h>\n#include <sgx_trts.h>\n#define HMAC_KEY_LENGTH 128\n'
        # Preserve the exact record definition and globals needed by this path;
        # the unused operator declarations need no out-of-line definitions.
        verify_h = (source/'Enclave/verify.h').read_text()
        header += re.search(r'typedef struct _sha256_hmac\{.*?\}sha256_hmac;', verify_h, re.S).group()+'\n'
        lines = original.read_text().splitlines()
        globals_ = '\n'.join(line for line in lines if line.startswith(('uint8_t hmac_key[', 'int training_num =', 'sha256_hmac *p_hmacu;')))+'\n'
        assert len(globals_.splitlines()) == 3
        diagnostic = ''
        decls = [line.strip() for line in (source/'Enclave/Enclave.edl').read_text().splitlines()
                 if any(re.search(r'\b'+n+r'\(', line) for n in FUNCTIONS[app])]
        includes = ''
    assert len(decls) == (3 if app == 'POSUP' else 2)
    (prepared/'Enclave.cpp').write_text(header+globals_+'\n\n'.join(bodies.values())+'\n'+diagnostic)
    (prepared/'Enclave.edl').write_text('enclave {\n from "sgx_tstdc.edl" import *;\n'+includes+' trusted {\n'+'\n'.join(decls)+'\n };\n};\n')
    for name, body in bodies.items():
        assert function((prepared/'Enclave.cpp').read_text(), name) == body
    record = dict(app=app, pin=pin, source=str(source), original=str(original),
                  archive_sha256=hashlib.sha256(data).hexdigest(),
                  files={str(p.relative_to(source)): sha(p) for p in sorted(source.rglob('*')) if p.is_file()},
                  function_hashes={n: hashlib.sha256(b.encode()).hexdigest() for n, b in bodies.items()},
                  prepared={str(p.relative_to(prepared)): sha(p) for p in prepared.iterdir() if p.is_file()},
                  adaptations=['Select exact required ECALL bodies and their needed globals; omit unrelated operations and headers.',
                               'Preserve original ECALL declarations and user_check; add pinned SDK-only tstdc import.',
                               'POSUP only: copied-output test observation ECALL for application set state; TYPE_ID remains int.',
                               'TrustFL only: retain all 60000 records, 28x28 images, 128-byte key and original allocation/lifetime behavior.'])
    (out/'prepared.json').write_text(json.dumps(record, indent=2)+'\n')
    return record
