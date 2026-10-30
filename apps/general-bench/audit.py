#!/usr/bin/env python3
"""Closed inventory for these five kernels; no general benchmark admission."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
sys.path.insert(0,str(ROOT/'tools'))
from encbound_inventory import get_marker, read_sections
from check_sdk_pins import SDK_BINARIES
from prepare import verify

APP={'driver','lists','heapsort','atax','gemm','jacobi'}
RUNTIME={'boundary_support','platform_layout','siphash','runtime','capability',
         'allocations','allocator','adapters'}
FUNCTIONS={'test_lists','benchmark_heapsort','kernel_atax','kernel_gemm','kernel_jacobi_2d'}
SERVICES={'malloc','free','memcpy','memset'}

def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def nm(p,flag):
    return {l.split()[-1] for l in subprocess.check_output(['nm',flag,str(p)],text=True).splitlines() if l.split()}
def sizes(p):
    text=subprocess.check_output(['size','-A',str(p)],text=True)
    sections={}
    for line in text.splitlines():
        fields=line.split()
        if len(fields)==3 and fields[1].isdigit(): sections[fields[0]]=int(fields[1])
    return sections

def audit(build,profile,codegen,sdk,trusted_opt,trusted_core,check_reuse,local_proofs,fast_paths,mac_algorithm):
    verify()
    protected=profile!='BASELINE'
    e=build/'enclave'
    trusted={'enclave_t'} | (RUNTIME if protected else set())
    if protected and trusted_core=='fused':
        trusted=(trusted-{'siphash','runtime','capability'})|{'check_core'}
    config=json.loads((build/'build-config.json').read_text())
    if config!={'profile':profile,'codegen':codegen,'trusted_opt':trusted_opt,'trusted_core':trusted_core,'check_reuse':check_reuse,'local_proofs':local_proofs,'fast_paths':fast_paths,'mac_algorithm':mac_algorithm}:
        raise ValueError('build configuration mismatch')
    objects=APP|trusted
    link=(e/'enclave.map').read_text().splitlines()
    loads={Path(l[5:]).resolve() for l in link if l.startswith('LOAD ') and l.endswith('.o')}
    if loads!={(e/(n+'.o')).resolve() for n in objects}: raise ValueError('object domain inventory mismatch')
    allowed=FUNCTIONS|{'__stack_chk_fail','memcpy','memset'}
    allowed |= ({'encbound_'+s for s in SERVICES}|{'encbound_require','encbound_stack_mint'} if protected else SERVICES)
    if protected and check_reuse!='off': allowed |= {'encbound_span_prepare','encbound_span_require'}
    records=[]
    for name in sorted(objects):
        obj=e/(name+'.o'); marker=get_marker(obj)
        if marker!=(profile if protected and name in APP else None): raise ValueError('wrong marker: '+name)
        syms=nm(obj,'--undefined-only')
        if name in APP:
            if syms-allowed: raise ValueError(f'{name}: unknown externals {syms-allowed}')
            definitions=subprocess.check_output(['nm','--defined-only',str(obj)],text=True)
            if re.search(r'^\S+\s+[bBdDgGsSC]\s+',definitions,re.M): raise ValueError('writable application global: '+name)
            ir=obj.with_suffix('.checked.ll').read_text()
            # No app source global region has been admitted for these kernels.
            globals_=[l for l in ir.splitlines() if l.startswith('@') and
                      not l.startswith(('@__encbound_instrumented','@llvm.compiler.used','@llvm.used'))]
            # Frontend-generated constant output-size table only. It lives in
            # this app object's read-only COMPAT section, never SDK rodata.
            if globals_ and not (name=='driver' and len(globals_)==1 and re.fullmatch(
                    r'@switch.table.bench_run = private unnamed_addr constant \[4 x i64\] \[i64 8, i64 32768, i64 1024, i64 18432\], align 8',globals_[0])):
                raise ValueError(f'{name}: unclassified IR globals {globals_}')
            if any(s.startswith('.rodata') for s in read_sections(obj)):
                raise ValueError('unclassified application rodata: '+name)
            if protected and re.search(r'\bcall\b[^\n]*@(?:malloc|free|memcpy|memset)\(',ir):
                raise ValueError('raw service call in checked IR: '+name)
            if protected and name!='driver' and not re.search(r'call i64 @encbound_(?:span_)?require',ir):
                raise ValueError('kernel has no access checks: '+name)
        records.append({'name':name,'domain':'application' if name in APP else 'trusted',
                        'sha256':digest(obj),'undefined':sorted(syms),'sections':sizes(obj),
                        'static_check_sites':len(re.findall(r'call i64 @encbound_(?:span_)?require',ir)) if name in APP else 0,
                        'span_access_sites':ir.count('call i64 @encbound_span_require') if name in APP else 0,
                        'span_prepare_sites':ir.count('call i64 @encbound_span_prepare') if name in APP else 0})
        if name in trusted and any(s.startswith('.encbound.appdata') for s in read_sections(obj)):
            raise ValueError('trusted data placed in COMPAT')
    section_output=subprocess.check_output(['readelf','-SW',str(e/'enclave.so')],text=True)
    appdata=[l for l in section_output.splitlines() if '.encbound.appdata ' in l]
    if len(appdata)!=1 or not re.search(r'\sA\s',appdata[0]) or re.search(r'\sWA?\s',appdata[0]):
        raise ValueError('application COMPAT section missing or writable')
    if 'bench_run' not in nm(e/'driver.o','--defined-only') or 'bench_run' not in nm(e/'enclave_t.o','--undefined-only'):
        raise ValueError('entry ownership mismatch')
    archives={l[5:] for l in link if l.startswith('LOAD ') and l.endswith('.a')}
    if {Path(p).name for p in archives}!={'libsgx_trts_sim.a','libsgx_tservice_sim.a','libsgx_tstdc.a','libsgx_tcrypto.a'}:
        raise ValueError('unexpected SDK archives')
    for path in archives:
        if digest(path)!=SDK_BINARIES['lib64/'+Path(path).name]: raise ValueError('SDK archive pin mismatch')
    manifest=json.loads((build/'generated/boundary-manifest.json').read_text())
    if manifest['profile']!=profile or manifest['ecalls']!=['bench_run'] or manifest['ocalls']:
        raise ValueError('bridge profile/interface mismatch')
    for path,expected in manifest['inputs'].items():
        if digest(path)!=expected: raise ValueError('bridge dependency drift: '+path)
    for path,expected in manifest['outputs'].items():
        if digest(build/'generated'/path)!=expected: raise ValueError('bridge output drift: '+path)
    if protected and 'encbound_boundary_alloc' not in nm(e/'enclave_t.o','--undefined-only'):
        raise ValueError('missing protected marshaling')
    if not protected:
        with tempfile.TemporaryDirectory(prefix='general-bench-stock-') as tmp:
            subprocess.run([str(sdk/'bin/x64/sgx_edger8r'),'--trusted','--untrusted',
                '--trusted-dir',tmp,'--untrusted-dir',tmp,'--search-path',str(sdk/'include'),
                str(HERE/'enclave.edl')],check=True)
            for name in ['enclave_t.c','enclave_t.h','enclave_u.c','enclave_u.h']:
                if (Path(tmp)/name).read_bytes()!=(build/'generated'/name).read_bytes():
                    raise ValueError('BASELINE differs from stock Intel bridge: '+name)
    rec={'profile':profile,'mode':'SIM','frontend':'-O2','codegen':codegen,
         'trusted_flags':trusted_opt+' -g; SGX debug enclave','trusted_core':trusted_core,'check_reuse':check_reuse,'local_proofs':local_proofs,'fast_paths':fast_paths,'mac_algorithm':mac_algorithm,'host_flags':'-O0 -g','fp_contract':'off',
         'objects':records,'archives':{p:digest(p) for p in sorted(archives)},
         'host':digest(build/'host/host'),'unsigned':digest(e/'enclave.so'),
         'signed':digest(e/'enclave.signed.so'),'image_sections':sizes(e/'enclave.so'),
         'image_bytes':(e/'enclave.signed.so').stat().st_size,
         'tools':{x:subprocess.check_output([x,'--version'],text=True).splitlines()[0] for x in ['clang-21','opt-21','cc']},
         'sources':{str(p.relative_to(ROOT)):digest(p) for p in sorted(HERE.rglob('*')) if p.is_file() and '__pycache__' not in str(p)},
         'shared_inputs':{str(p.relative_to(ROOT)):digest(p) for p in
             [ROOT/'tools/encbound-cc.sh', ROOT/'tools/mark_appdata_sections.sh',
              ROOT/'tools/check_sdk_pins.py',ROOT/'tools/sgx_metadata.py',
              ROOT/'build/pass/encbound_pass.so',ROOT/'pass/encbound_pass.cpp',ROOT/'pass/encbound_fast_paths.h',
              ROOT/'sdk/enclave.lds',ROOT/'sdk/enclave_sections.lds',
              ROOT/'sdk/platform_layout.c',ROOT/'sdk/boundary_support.c',
              ROOT/'sdk/boundary_support.h',ROOT/'sdk/modified_bridge.h',
              *sorted((ROOT/'runtime').glob('*.[ch]')),*sorted((ROOT/'include').glob('*.h'))]},
         'limitations':'Static site counts are not dynamic counts or a final-machine-code proof.'}
    (build/'inventory.json').write_text(json.dumps(rec,indent=2)+'\n')
    print('GENERAL BENCH INVENTORY PASS',profile)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True)
    p.add_argument('--profile',choices=['BASELINE','RADIX_ONLY','MAC27'],required=True)
    p.add_argument('--trusted-opt',choices=['-O0','-O2'],required=True)
    p.add_argument('--trusted-core',choices=['separate','fused'],required=True)
    p.add_argument('--mac-algorithm',choices=['siphash24','aes128_cmac'],required=True)
    p.add_argument('--fast-paths',choices=['off','inline','loops'],required=True)
    p.add_argument('--local-proofs',type=int,choices=[0,1],required=True)
    p.add_argument('--check-reuse',choices=['off','block','loop'],required=True)
    p.add_argument('--codegen',required=True);p.add_argument('--sdk',type=Path,required=True);a=p.parse_args()
    audit(a.build,a.profile,a.codegen,a.sdk,a.trusted_opt,a.trusted_core,a.check_reuse,a.local_proofs,a.fast_paths,a.mac_algorithm)
