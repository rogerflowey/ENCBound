"""Admission follows Intel marshaling operations; includes stock syntax/equality controls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT/"build/integration/edl-transport-admission"
WORK.mkdir(parents=True,exist_ok=True)
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
GEN = ROOT/'build/edger8r/sgx_edger8r'
ENV = {k:v for k,v in os.environ.items() if not k.startswith('ENCBOUND_BRIDGE_')}

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

HEADER = '''#include <stdint.h>
typedef struct Fixed { uint32_t words[2]; } Fixed;
typedef struct Opaque Opaque;
typedef int *IntPtr;
typedef int IntArray[3];
'''
BUFFER = ('public int entry([in,out,size=n] T *p, size_t n);',
          'void emit([in,out,size=n] T *p, size_t n);')

def case(name, addition='', functions=BUFFER, records=None, preamble='', expected=None):
    return dict(name=name,header=HEADER+addition,functions=functions,
                records=records or {},preamble=preamble,expected=expected)

CASES = [
    case('named-fixed-control','typedef struct T { int x; } T;',expected='accept'),
    case('incomplete-explicit-bytes',functions=tuple(s.replace('T *','Opaque *') for s in BUFFER),expected='accept'),
    case('incomplete-sizeof-control',functions=tuple(s.replace('T *','Opaque *').replace('size=n','count=n') for s in BUFFER),expected='stock-syntax-reject'),
    case('anonymous-record','typedef struct { int x; } T;',expected='accept'),
    case('anonymous-member','typedef struct T { struct { int x; }; } T;',expected='accept'),
    case('zero-length-tail','typedef struct T { int n; unsigned char data[0]; } T;',expected='accept'),
    case('int128-buffer','typedef unsigned __int128 T;',expected='accept'),
    case('complex-buffer','typedef float _Complex T;',expected='accept'),
    case('scoped-tag','typedef struct T { int x; } T;\nstatic void unrelated(void) { struct T { void *p; }; }',expected='accept'),
    case('scoped-typedef','typedef struct T { int x; } T;\nstatic void unrelated(void) { typedef void *T; }',expected='accept'),
    case('usercheck-pointer-typedef',functions=('public int entry([user_check,isptr] IntPtr p);','void emit([user_check,isptr] IntPtr p);'),expected='accept'),
    case('usercheck-array-typedef',functions=('public int entry([user_check,isary] IntArray p);','void emit([user_check,isary] IntArray p);'),expected='accept'),
    case('shallow-pointer-array',functions=('public int entry([in,out,count=n] int **p, size_t n);','void emit([in,out,count=n] int **p, size_t n);'),expected='accept'),
    case('long-double-value','typedef long double Extended;',functions=('public Extended entry(Extended x);','Extended emit(Extended x);'),expected='reject'),
    case('record-result',functions=('public Fixed entry();','Fixed emit();'),records={'Fixed':{'header':'types.h'}},expected='reject'),
    case('enum-value-record','typedef enum E { YES=1 } E;\ntypedef struct T { E e; } T;',functions=('public int entry(T value);','int emit(T value);'),records={'T':{'header':'types.h'}},expected='reject'),
    case('bitfield-value-record','typedef struct T { unsigned bits:2; } T;',functions=('public int entry(T value);','int emit(T value);'),records={'T':{'header':'types.h'}},expected='reject'),
    case('union-value-record','typedef union T { unsigned x; float y; } T;',functions=('public int entry(T value);','int emit(T value);'),records={'T':{'header':'types.h'}},expected='reject'),
    case('packed-value-record','typedef struct __attribute__((packed)) T { char x; int y; } T;',functions=('public int entry(T value);','int emit(T value);'),records={'T':{'header':'types.h'}},expected='reject'),
    case('sgx-prefix',functions=('public int sgx_application_entry();','void emit();'),expected='accept'),
    case('completed-forward','struct T; typedef struct T T; struct T { int x; }; struct T;',expected='accept'),
    case('incomplete-tag-bytes',functions=tuple(s.replace('T *','struct Opaque *') for s in BUFFER),expected='accept'),
    case('shallow-pointer-typedef','typedef int **T;',functions=('public int entry([in,out,isptr,count=n] T p, size_t n);','void emit([in,out,isptr,count=n] T p, size_t n);'),expected='accept'),
    case('shallow-array-typedef','typedef int *T[3];',functions=('public int entry([in,out,isary] T p);','void emit([in,out,isary] T p);'),expected='accept'),
    case('shallow-union','typedef union T { int *p; int n; } T;',expected='accept'),
    case('errno-mode',functions=('public int entry();','int emit() propagate_errno;'),expected='accept'),
    case('flexible-tail' ,'typedef struct T { int n; unsigned char data[]; } T;',expected='accept'),
    case('shallow-fields','typedef struct T { void *pointer; void (*callback)(void); } T;',expected='accept'),
    case('usercheck-opaque',functions=('public int entry([user_check] Opaque *p);','void emit([user_check] Opaque *p);'),expected='accept'),
    case('pointer-result',functions=('public Opaque *entry([user_check] Opaque *p);','Opaque *emit([user_check] Opaque *p);'),expected='accept'),
    case('pointer-alias-result',functions=('public IntPtr entry();','IntPtr emit();'),expected='accept'),
    case('callback-result','typedef void (*Callback)(void);',functions=('public Callback entry();','Callback emit();'),expected='reject'),
    case('scalar-isary',functions=('public int entry([user_check,isary] int p);','void emit();'),expected='stock-reject'),
    case('pointer-isary',functions=('public int entry([user_check,isary] IntPtr p);','void emit();'),expected='reject'),
    case('overaligned-buffer','typedef struct __attribute__((aligned(32))) T { int x; } T;',expected='reject'),
    case('sdk-primitive-name',functions=('public int entry();','void sgx_ocfree();'),expected='stock-syntax-reject'),
    case('generated-name-collision',functions=('public int entry(); public int sgx_entry();','void emit();'),expected='stock-syntax-reject'),
    case('explicit-deep-copy',functions=('public int entry([in] struct Deep *p);','void emit([in] struct Deep *p);'),preamble='struct Deep { size_t n; [size=n] unsigned char *p; };',expected='reject'),
]
rows = []
sources = {}
for p in (ROOT/'tools/edger8r').iterdir():
    if p.suffix in ('.ml','.mll','.mly'):
        assert p.read_bytes()==(ROOT/'build/edger8r'/p.name).read_bytes(),p
        sources[str(p)]=sha(p)

def run(command,log):
    p=subprocess.run(list(map(str,command)),env=ENV,capture_output=True,text=True,timeout=60)
    log.write_text(p.stdout+p.stderr)
    return dict(command=list(map(str,command)),returncode=p.returncode,log=str(log),log_sha256=sha(log))

for c in CASES:
    work=WORK/c['name'];work.mkdir(exist_ok=True)
    (work/'types.h').write_text(c['header'])
    edl=work/'probe.edl'
    edl.write_text('enclave { include "types.h"\n'+c['preamble']+'\ntrusted { '+c['functions'][0]+' };\nuntrusted { '+c['functions'][1]+' };\n};\n')
    policy=work/'interface.json'
    policy.write_text(json.dumps({'records':c['records'],'sdk_only_imports':{}})+'\n')
    stock=work/'stock';stock.mkdir(exist_ok=True)
    gen=run([SDK/'bin/x64/sgx_edger8r','--search-path',work,'--trusted','--trusted-dir',stock,'--untrusted','--untrusted-dir',stock,edl],work/'stock.log')
    syntax=None
    if gen['returncode']==0:
        syntax=run(['cc','-fsyntax-only','-I'+str(work),'-I'+str(SDK/'include'),'-I'+str(ROOT/'tests/fixtures/modified_bridge'),stock/'probe_t.c',stock/'probe_u.c'],work/'stock-syntax.log')
    observations=[]
    for profile in ('BASELINE','RADIX_ONLY','MAC27'):
        out=work/profile
        cmd=['python3',ROOT/'tools/modified_bridge.py','--edl',edl,'--interface',policy,'--generator',GEN,'--profile',profile,'--out-dir',out,'--search-path',work]
        cmd+=['--cflag=-I'+str(p) for p in (work,SDK/'include',ROOT/'sdk',ROOT/'include',ROOT/'tests/fixtures/modified_bridge')]
        admission=run(cmd,work/(profile+'.log'))
        text=Path(admission['log']).read_text()
        diagnostic=next((s for s in text.splitlines() if 'ENCBound:' in s or 'error:' in s or 'Assertion' in s),None)
        observations.append(dict(profile=profile,admission=admission,diagnostic=diagnostic))
        if c['expected']=='accept':
            assert admission['returncode']==0,admission
            if profile=='BASELINE':
                suffixes=('_t.h','_u.c','_u.h') if c['name']=='errno-mode' else ('_t.c','_t.h','_u.c','_u.h')
                assert all((stock/('probe'+s)).read_bytes()==(out/('probe'+s)).read_bytes() for s in suffixes)
                if c['name']=='errno-mode':
                    assert '__encbound_app_errno_store(errno);' in (out/'probe_t.c').read_text()
                    disabled=work/'disabled';disabled.mkdir(exist_ok=True)
                    run([GEN,'--search-path',work,'--trusted','--trusted-dir',disabled,'--untrusted','--untrusted-dir',disabled,edl],work/'disabled.log')
                    assert all((stock/('probe'+s)).read_bytes()==(disabled/('probe'+s)).read_bytes() for s in ('_t.c','_t.h','_u.c','_u.h'))
        elif c['expected'] in ('reject','stock-reject','stock-syntax-reject'):
            assert admission['returncode']!=0,admission
        assert admission['returncode']==0 or not any(out.glob('*_t.c')), 'Rejected interface published bridge'
    if c['expected']=='stock-reject':
        assert gen['returncode']!=0
    elif c['expected']=='stock-syntax-reject':
        assert gen['returncode']==0 and syntax['returncode']!=0
    else:
        assert gen['returncode']==0 and syntax['returncode']==0,(c['name'],gen,syntax)
    print(c['name']+': stock='+str(gen['returncode'])+'/'+str(syntax['returncode'] if syntax else None)+'; ENCBound='+str([o['admission']['returncode'] for o in observations])+'; '+str(observations[-1]['diagnostic']))
    rows.append(dict(case=c,stock_generation=gen,stock_syntax=syntax,profiles=observations))

(WORK/'results.json').write_text(json.dumps({'scope':'native generation/syntax/admission only','generator_sha256':sha(GEN),'generator_sources':sources,'script_sha256':sha(Path(__file__)),'rows':rows},indent=2)+'\n')
print('EDL TRANSPORT ADMISSION PASS:', len(rows), 'fixtures /', 3*len(rows), 'profile rows; stock syntax and BASELINE equality')
