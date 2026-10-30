#!/usr/bin/env python3
"""Build/run actual emitted bridges and verify reproducibility/admission."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[1] / 'deps/sgxsdk')))))
APP = ROOT/'tests/fixtures/wallet'
BUILD = ROOT/'build/tests/modified-bridge'
GEN = ROOT/'build/edger8r/sgx_edger8r'
EDL = ROOT/'tests/fixtures/wallet/enclave.edl'
INTERFACE = ROOT/'tests/fixtures/wallet/boundary-interface.json'
flags = ['-I'+str(p) for p in (ROOT/'tests/fixtures/modified_bridge', SDK/'include',
         ROOT/'include', ROOT/'runtime', ROOT/'sdk', ROOT/'tests', APP/'include')]

def generate(out, profile, source=EDL, interface=INTERFACE, success=True):
    cmd=['python3',str(ROOT/'tools/modified_bridge.py'),'--edl',str(source),
         '--interface',str(interface),'--generator',str(GEN),'--out-dir',str(out),
         '--profile',profile]
    for p in (SDK/'include',APP/'include',ROOT/'sdk',ROOT/'include'):
        cmd += ['--search-path',str(p)]
    cmd += ['--cflag='+f for f in flags]
    result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if (result.returncode==0) != success:
        raise AssertionError(result.stdout)
    if not success:
        assert 'modified-bridge: FAIL:' in result.stdout
        assert not list(out.glob('*_t.c')), 'rejected interface published bridge'
    return result.stdout

def main():
    BUILD.mkdir(parents=True,exist_ok=True)
    subprocess.run(['make','-C',str(ROOT/'tools/edger8r')],check=True)
    sources=[ROOT/'tests/modified_bridge_test.c', ROOT/'tests/fake_platform.c',
             ROOT/'sdk/boundary_support.c']
    sources += [ROOT/'runtime'/n for n in ('siphash.c','runtime.c','capability.c',
                                         'allocations.c','allocator.c','adapters.c')]
    for profile in ('BASELINE','RADIX_ONLY','MAC27'):
        out=BUILD/profile
        print(generate(out,profile),end='')
        before={p.name:p.read_bytes() for p in out.iterdir()}
        generate(out,profile)
        assert before=={p.name:p.read_bytes() for p in out.iterdir()}, 'nondeterministic output'
        with tempfile.TemporaryDirectory(dir=BUILD) as temp:
            fresh=Path(temp)/'fresh'
            generate(fresh,profile)
            for name in ('enclave_t.c','enclave_t.h','enclave_u.c','enclave_u.h','admitted-ocalls.txt'):
                assert (fresh/name).read_bytes()==before[name], 'fresh generation differs'
        exe=BUILD/('test-'+profile)
        cmd=['cc','-O0','-g','-Wall','-Wextra','-Wno-unused-parameter','-I'+str(out)]+flags
        if profile!='BASELINE': cmd += ['-DENCBOUND_PROTECTED']
        if profile=='MAC27': cmd += ['-DENCBOUND_MAC27']
        cmd += [str(p) for p in sources]+['-o',str(exe)]
        for name in ('encbound_malloc','encbound_free','malloc','free','encbound_platform_init'):
            cmd += ['-Wl,--wrap='+name]
        subprocess.run(cmd,check=True)
        subprocess.run([str(exe)],check=True)
    # Disabled patch mode must match the pinned binary, not just compile.
    stock=BUILD/'stock';stock.mkdir(exist_ok=True)
    subprocess.run([str(SDK/'bin/x64/sgx_edger8r'),'--search-path',str(APP/'include'),
        '--search-path',str(SDK/'include'),'--trusted','--trusted-dir',str(stock),
        '--untrusted','--untrusted-dir',str(stock),str(EDL)],check=True)
    for name in ('enclave_t.c','enclave_t.h','enclave_u.c','enclave_u.h'):
        assert (stock/name).read_bytes()==(BUILD/'BASELINE'/name).read_bytes(), name
    print('PASS: baseline matches installed Intel bridge byte-for-byte')
    # Unsupported semantics must not silently enter the patched templates.
    variants={
        'ocall_user_check_mixed':('[in, string]const char* str', '[user_check,in,string]const char* str'),
        'const_output':('wallet_t* wallet','const wallet_t* wallet'),
        'unknown_attribute':('[in, string]','[in, string, unknown]'),
        'string_size':('[in, string]','[in, string, size=wallet_size]'),
        'attribute_value':('[in, string]','[in=1, string]'),
        'private_ecall':('public int ecall_create_wallet','int ecall_create_wallet'),
        'switchless':('size_t wallet_size\n        );','size_t wallet_size\n        ) transition_using_threads;'),
        'unclassified_import':('sgx_tstdc.edl','unknown.edl'),
    }
    with tempfile.TemporaryDirectory(dir=BUILD) as temp:
        temp=Path(temp)
        for name,(old,new) in {
            'shallow_pointer_array':('wallet_t* wallet','wallet_t** wallet'),
            'ocall_user_check':('[in, string]const char* str', '[user_check]const char* str'),
            'combined_extent':('size=item_size','size=item_size,count=item_size'),
            'signed_size':('size_t wallet_size','int wallet_size'),
        }.items():
            source=temp/(name+'.edl');source.write_text(EDL.read_text().replace(old,new))
            generate(temp/(name+'-out'),'MAC27',source=source)
        for name,(old,new) in variants.items():
            assert old in EDL.read_text(), name
            print('checking rejection:',name,flush=True)
            source=temp/(name+'.edl');source.write_text(EDL.read_text().replace(old,new))
            generate(temp/(name+'-out'),'MAC27',source=source,success=False)
        config=json.loads(INTERFACE.read_text());config['input_cap']=4096
        policy=temp/'policy.json';policy.write_text(json.dumps(config))
        generate(temp/'policy-out','MAC27',interface=policy,success=False)
        config=json.loads(INTERFACE.read_text())
        config['sdk_only_imports']['sgx_tstdc.edl']['sha256']='0'*64
        policy.write_text(json.dumps(config))
        generate(temp/'wrong-import-out','MAC27',interface=policy,success=False)
        config=json.loads(INTERFACE.read_text())
        config['sdk_only_imports']['sgx_tstdc.edl']['domain']='application'
        policy.write_text(json.dumps(config))
        generate(temp/'wrong-domain-out','MAC27',interface=policy,success=False)
    print('PASS: unsupported shapes and supplementary policy rejected')
    print('MODIFIED BRIDGE GENERATION PASS')

if __name__=='__main__': main()
