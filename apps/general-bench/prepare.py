#!/usr/bin/env python3
"""Pin-check upstream bytes and extract the five bounded benchmark kernels.

Generated sources are application code, never trusted services. This script is
the complete adaptation recipe; original files and licenses remain unchanged.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
UP = HERE / 'upstream'

def verify():
    manifest = json.loads((UP / 'manifest.json').read_text())
    for name, record in manifest['files'].items():
        if hashlib.sha256((UP / name).read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('upstream pin mismatch: ' + name)

def function(source, name):
    match = re.search(r'\b' + name + r'\s*\(', source)
    if match is None:
        raise ValueError('missing function: ' + name)
    start = match.start()
    brace = source.index('{', match.end())
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

def prepare(out):
    verify()
    out.mkdir(parents=True, exist_ok=True)
    shoot = UP / 'SingleSource/Benchmarks/Shootout'
    poly = UP / 'SingleSource/Benchmarks/Polybench'
    prefix = '/* Generated from pinned LLVM test-suite; see upstream licenses and PROVENANCE.md. */\n'
    text = (shoot / 'lists.c').read_text()
    text = text[:text.index('int main(')]
    first = text.index('void list_print(')
    last = text.index('DLL *list_new()', first)
    text = text[:first] + text[last:]
    # Preserve every correctness predicate; replace terminal stdio/exit with
    # cleanup and an error result. No success predicate is removed.
    text = re.sub(r'    printf\(.*?\);\s*exit\(1\);', '    goto fail;', text, flags=re.S)
    text = text.replace('  return(len);', '  return(len);\nfail:\n  free(li1); free(li2); free(li3);\n  return -1;')
    text = text.replace('#include <stdio.h>\n', '')
    # Ordinary allocation failure is an explicit error instead of a raw NULL
    # dereference. These checks are identical in all profiles.
    text = text.replace('  l->next = l;', '  if (!l) return NULL;\n  l->next = l;')
    text = text.replace('  from--;', '  if (!l) return NULL;\n  from--;')
    text = text.replace('  for (i=0, j=1, xp=x;', '  if (!l) return NULL;\n  for (i=0, j=1, xp=x;')
    text = text.replace('  DLL *li2 = list_copy(li1);', '  if (!li1) return -1;\n  DLL *li2 = list_copy(li1);\n  if (!li2) { free(li1); return -1; }')
    text = text.replace('  DLL *li3 = list_new();', '  DLL *li3 = list_new();\n  if (!li3) { free(li1); free(li2); return -1; }')
    if re.search(r'\b(printf|exit|puts)\s*\(', text):
        raise ValueError('unadapted list service')
    (out/'lists.c').write_text(prefix + text)
    text = (shoot/'heapsort.c').read_text()
    (out/'heapsort.c').write_text(prefix + '#define heapsort benchmark_heapsort\nvoid\n' + function(text,'heapsort') + '\n')
    paths = {'atax':'linear-algebra/kernels/atax/atax.c',
             'gemm':'linear-algebra/blas/gemm/gemm.c',
             'jacobi':'stencils/jacobi-2d/jacobi-2d.c'}
    macros = '''#include "bench.h"
#define DATA_TYPE double
#define SCALAR_VAL(x) x
#define POLYBENCH_1D(v,d,n) v[d]
#define POLYBENCH_2D(v,d,e,m,n) v[d][e]
'''
    dims = {'atax':'#define M ATAX_N\n#define N ATAX_N\n#define _PB_M m\n#define _PB_N n\n',
            'gemm':'#define NI GEMM_N\n#define NJ GEMM_N\n#define NK GEMM_N\n#define _PB_NI ni\n#define _PB_NJ nj\n#define _PB_NK nk\n',
            'jacobi':'#define N JACOBI_N\n#define _PB_N n\n#define _PB_TSTEPS tsteps\n'}
    for case, path in paths.items():
        name = 'kernel_jacobi_2d' if case == 'jacobi' else 'kernel_'+case
        body = function((poly/path).read_text(), name)
        (out/(case+'.c')).write_text(prefix + macros + dims[case] + 'void\n' + body + '\n')
    (out/'adapted-hashes.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(out.glob('*.c'))}, indent=2)+'\n')

if __name__ == '__main__':
    if sys.argv[1] == '--mark':
        obj=Path(sys.argv[2]);raw=Path(str(obj)+'.raw');shutil.copy2(obj,raw)
        sys.path.insert(0,str(HERE.parent.parent/'tools'))
        from encbound_inventory import read_sections
        if any(s.startswith('.rodata') for s in read_sections(raw)):
            subprocess.run([str(HERE.parent.parent/'tools/mark_appdata_sections.sh'),str(raw),str(obj)],check=True)
    else:
        prepare(Path(sys.argv[1]))
