#!/usr/bin/env python3
"""Diagnostic release build of the pinned USIG closure (-DNDEBUG application units).

Identical to build.py except that C/libc++ assertions are disabled in the
application units.  Used only by release_control.py; the four-row matrix
evidence keeps using the unchanged build.py."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
from prepare import HERE, ROOT, PINS, prepare, sha

SDK = Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))
SDK_SRC = Path(os.environ.get('PINNED_SRC', str(ROOT/'deps/intel-sgx')))
CRYPTO = 'ed25519 fe25519 ge25519 sc25519 sha512hash sha512blocks'.split()
MAPPINGS = {'sgx_ecc256_open_context':'encbound_usig_ecc_open',
            'sgx_ecc256_close_context':'encbound_usig_ecc_close',
            'sgx_ecdsa_sign':'encbound_usig_ecdsa_sign',
            'sgx_hmac_sha256_msg':'encbound_usig_hmac',
            'sgx_read_rand':'encbound_usig_rand'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--profile', choices=('BASELINE','RADIX_ONLY','MAC27'), required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--base', choices=('0x40000000','0x140000000'), default='0x40000000')
    ap.add_argument('--admission-only', action='store_true')
    ap.add_argument('--vector', action='store_true', help='Diagnostic default-vectorized frontend')
    args = ap.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    for n in ('prepared','generated','objects','ir','enclave'):(out/n).mkdir(exist_ok=True)
    record=dict(profile=args.profile,base=args.base,preset='all-compat-v1',commands=[],source=PINS)
    record['no_assert']=True
    def save(): (out/'probe.json').write_text(json.dumps(record,indent=2)+'\n')
    def run(name, cmd, env=None, fail=True, cwd=ROOT):
        cmd=list(map(str,cmd));r=subprocess.run(cmd,env=env,cwd=cwd,text=True,capture_output=True,timeout=600)
        log=out/(name+'.log');log.write_text(r.stdout+r.stderr)
        record['commands'].append(dict(name=name,command=cmd,returncode=r.returncode,log=str(log),sha256=sha(log)))
        save();print(name,'PASS' if r.returncode==0 else 'FAIL',flush=True)
        if fail and r.returncode:raise SystemExit((r.stdout+r.stderr)[-5000:]+'\nSee '+str(log))
        return r
    upstream=prepare();prepared=out/'prepared';g=out/'generated'
    shutil.copytree(upstream,prepared,dirs_exist_ok=True)
    # Private application printf name prevents an application/SDK symbol collision.
    for n in ('trusted/usig_enclave.cpp','trusted/usig_enclave.h'):
        p=prepared/n;s=p.read_text();assert s.count('int printf(')==1
        p.write_text(s.replace('int printf(', 'int app_usig_printf('))
    # The upstream Makefile compiles C crypto as C++. Clang models its external
    # const aggregate declaration as mutable in C++, unlike the RO definition.
    # Use the original C sources as C, with an explicit C API for the C++ caller.
    api=prepared/'trusted/edd25519/crypto_api.h';s=api.read_text()
    s=s.replace('#include <stdlib.h>', '#include <stdlib.h>\n#ifdef __cplusplus\nextern "C" {\n#endif')
    s=s.replace('#endif /* crypto_api_h */', '#ifdef __cplusplus\n}\n#endif\n#endif /* crypto_api_h */')
    api.write_text(s)
    edl=prepared/'trusted/usig_enclave.edl';s=edl.read_text()
    edl.write_text(s.replace('enclave {','enclave {\n    from "sgx_tstdc.edl" import *;',1))
    record['adaptations']=['Rename the unused application printf definition/declaration to app_usig_printf; retain formatting bodies.',
        'Import pinned SDK-only sgx_tstdc.edl for the trusted runtime; original five ECALLs and print OCALL unchanged.',
        'Complete missing randombytes/crypto_verify_32 definitions as application-owned crypto_support.c.',
        'Use C++17 private serial libc++ configuration; compile the original six crypto .c units as C with explicit extern-C crypto_api.h declarations.',
        'Scalar frontend for application units unless --vector diagnostic is selected.']
    record['prepared']={str(p.relative_to(prepared)):sha(p) for p in prepared.rglob('*') if p.is_file()}
    includes=['-I'+str(x) for x in (prepared/'trusted',prepared/'include',g,ROOT/'include',ROOT/'runtime',ROOT/'sdk',SDK/'include',SDK/'include/tlibc',SDK_SRC/'common/inc/internal')]
    common=['-O2','-g','-fno-builtin','-fno-common','-nostdinc','-fpie','-fvisibility=hidden','-ffunction-sections','-fdata-sections','-fstack-protector-strong',*includes]
    noassert=['-DNDEBUG']
    common += noassert
    scalar=[] if args.vector else ['-fno-vectorize','-fno-slp-vectorize']
    env=dict(os.environ,ENCBOUND_PROFILE=args.profile,ENCBOUND_LIBCXX_PREPARED=str(ROOT/'build/go-consensus-usig/libcxx-prepared'))
    env.update(ENCBOUND_CXX_EH='0',ENCBOUND_KEEP_GEP_FLAGS='0',ENCBOUND_POST_INSTCOMBINE='0')
    # Entire invocation, including both libraries, is always wrapped in the preset.
    preset=[ROOT/'tools/with-integration-defaults.sh']
    run('sdk-pins',['python3',ROOT/'tools/check_sdk_pins.py','--sdk',SDK,'--pinned',SDK_SRC])
    run('bridge',['python3',ROOT/'tools/modified_bridge.py','--edl',edl,'--interface',HERE/'boundary-interface.json',
        '--generator',ROOT/'build/edger8r/sgx_edger8r','--out-dir',g,'--profile',args.profile,
        '--search-path',prepared/'trusted','--search-path',SDK/'include',*['--cflag='+f for f in includes+['-nostdinc']]])
    if args.profile=='BASELINE':
        stock=out/'stock';stock.mkdir(exist_ok=True)
        run('stock-bridge',[SDK/'bin/x64/sgx_edger8r',edl,'--search-path',prepared/'trusted',
            '--search-path',SDK/'include','--trusted-dir',stock,'--untrusted-dir',stock])
        record['stock_equality']={}
        for suffix in ('_t.c','_t.h','_u.c','_u.h'):
            name='usig_enclave'+suffix
            assert (g/name).read_bytes()==(stock/name).read_bytes(),'stock bridge mismatch '+name
            record['stock_equality'][name]=sha(stock/name)
    caller=prepared/'trusted/usig_enclave.cpp'
    extra=[*includes,'-Dvsnprintf=app_fmt_vsnprintf',*scalar,'-g',*noassert]
    run('libcxx-prepare',['python3',ROOT/'apps/libcxx/prepare.py'],env)
    run('libcxx',[*preset,'python3',ROOT/'apps/libcxx/build.py','--profile',args.profile,'--out-dir',out/'libcxx',
        '--caller',caller,*['--caller-flag='+f for f in extra]],env)
    cxx=json.loads((out/'libcxx/build.json').read_text())
    run('formatter', [*preset,'python3',ROOT/'apps/libc-format/build.py','--profile',args.profile,'--out-dir',out/'libc-format',
        '--caller',caller,'--caller-no-namespace',*['--caller-flag='+f for f in cxx['flags']+extra]],env)
    app_sources=[caller]+[prepared/'trusted/edd25519'/f'{n}.c' for n in CRYPTO]+[HERE/'crypto_support.c']
    flags={str(src):cxx['flags']+extra if src==caller else common+scalar+['-std=c99'] for src in app_sources}
    if args.profile!='BASELINE':
        src=g/'usig_enclave_app.c';app_sources.append(src);flags[str(src)]=common+scalar
    definitions=set()
    for src in app_sources:
        ir=out/'ir'/(src.stem+'.ll')
        run(src.stem+'-inventory',['clang-21',*flags[str(src)],'-S','-emit-llvm',src,'-o',ir])
        text=ir.read_text()
        definitions.update(re.findall(r'^define (?!internal |private ).*?@([^ (]+)\(',text,re.M))
        definitions.update(re.findall(r'^@([^ ]+) = .*?alias ',text,re.M))
    admitted=out/'admitted.txt'
    admitted.write_text('\n'.join(sorted(definitions))+'\n'+
        (out/'libcxx/admitted.txt').read_text()+(out/'libc-format/admitted.txt').read_text()+
        (g/'admitted-app.txt').read_text()+(g/'admitted-ocalls.txt').read_text()+
        '\n'.join(n+' = '+v for n,v in MAPPINGS.items())+'\n')
    env['ENCBOUND_ADMITTED']=str(admitted)
    record.update(definitions=sorted(definitions),adapter_mappings=MAPPINGS,frontend_flags=flags)
    record['inputs']={str(p):sha(p) for p in [HERE/'build_noassert.py',HERE/'build.py',HERE/'prepare.py',HERE/'pins.json',HERE/'adapters.c',HERE/'crypto_support.c',HERE/'boundary-interface.json',ROOT/'config/integration.env',ROOT/'build/pass/encbound_pass.so',ROOT/'build/edger8r/sgx_edger8r',ROOT/'tools/encbound-cc.sh',ROOT/'tools/modified_bridge.py']}
    rows=[];app=[];original=[]
    run('adapters-compile',['clang-21',*common,'-c',HERE/'adapters.c','-o',out/'objects/usig-adapters.o'])
    for src in app_sources:
        obj=out/'objects'/(src.stem+'.o')
        r=run(src.stem+'-application',[*preset,ROOT/'tools/encbound-cc.sh',src,obj,*flags[str(src)]],env,False)
        rows.append(dict(source=str(src),object=str(obj),returncode=r.returncode))
        if not r.returncode:
            placed=out/'enclave'/(src.stem+'.o')
            run(src.stem+'-placement',[*preset,ROOT/'tools/mark_appdata_sections.sh',obj,placed],env)
            app.append(placed);original.append(obj)
    record.update(application_rows=rows,admission_passed=all(x['returncode']==0 for x in rows))
    save()
    if not record['admission_passed']:raise SystemExit(1)
    if args.admission_only:return
    # Libraries are ordinary application objects, including all selected bodies.
    for library in ('libcxx','libc-format'):
        app += list(map(Path,json.loads((out/library/'build.json').read_text())['objects']))
    from finish import finish
    finish(args,out,record,app,original,common,run)

if __name__=='__main__':main()
