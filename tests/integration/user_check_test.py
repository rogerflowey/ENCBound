#!/usr/bin/env python3
"""Execute ECALL user_check pass-through with instrumented app accesses.

Native fake platform, actual emitted Intel bridges and real ENCBound runtime.
No SGX execution or hardware isolation is implied by these tests.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/integration/user-check'
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
GEN = ROOT / 'build/edger8r/sgx_edger8r'
OUT.mkdir(parents=True, exist_ok=True)
(OUT / 'interface.json').write_text('{"records":{},"sdk_only_imports":{}}\n')
DECL = 'public int probe([user_check] char **argv, int action, size_t expected);'
(OUT / 'probe.edl').write_text('enclave { trusted { ' + DECL + ' }; };\n')
(OUT / 'app.c').write_text(r'''
#include <stdint.h>
#include <stddef.h>
int probe(char **argv, int action, size_t expected) {
    if (action == 0) return (uintptr_t)argv == expected;
    if (action == 1) return (unsigned char)argv[0][0];
    if (action == 2) { argv[0][0] = 'z'; return 7; }
    if (action == 3) { argv[0] = argv[1]; return 8; }
    return -1;
}
''')
(OUT / 'test.c').write_text(r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
int bridge_copy_fail;
#include "probe_t.c"
int sgx_is_outside_enclave(const void *p, size_t n) {
    return p && encbound_is_outside_enclave(p, n);
}
int sgx_is_within_enclave(const void *p, size_t n) {
    uintptr_t b=encbound_enclave_base(), a=(uintptr_t)p;
    return a>=b && a-b<encbound_enclave_size() && n<=encbound_enclave_size()-(a-b);
}
static int call(char **p, int action, size_t expected) {
    ms_probe_t m={.ms_argv=p,.ms_action=action,.ms_expected=expected};
    assert(sgx_probe(&m)==SGX_SUCCESS);
    return m.ms_retval;
}
#ifdef ENCBOUND_PROTECTED
static void reject(char **p, int action, int code, unsigned char *unchanged) {
    pid_t child=fork(); assert(child>=0);
    if (!child) {
        unsigned char before=unchanged ? *unchanged : 0;
        fake_abort_active=1;
        if (!setjmp(fake_abort_env)) { call(p,action,0); assert(0); }
        assert(fake_abort_code==code);
        if (unchanged) assert(*unchanged==before);
        _exit(0); /* test-only caught abort never resumes the enclave session */
    }
    int status; assert(waitpid(child,&status,0)==child);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
#endif
int main(void) {
    /* Even NULL/unmapped/noncanonical values pass unchanged when unused. */
    uintptr_t bits[]={0,1,UINT64_C(1)<<48,UINT64_MAX};
    for (unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i)
        assert(call((char **)bits[i],0,bits[i])==1);
    char first[]="Abc", second[]="Def";
    char *args[]={first,second};
    assert(call(args,0,(uintptr_t)args)==1);
    assert(call(args,1,0)=='A');
    assert(call(args,2,0)==7 && first[0]=='z');
    assert(call(args,3,0)==8 && args[0]==second);
    second[0]='Q'; assert(call(args,1,0)=='Q');
#ifdef ENCBOUND_PROTECTED
    unsigned char *trusted=(void *)encbound_enclave_base();
    *trusted=0x31;
    reject((char **)trusted,1,ENCBOUND_ERR_POLICY,trusted);
    args[0]=(char *)trusted;
    reject(args,1,ENCBOUND_ERR_POLICY,trusted);
    reject(args,2,ENCBOUND_ERR_POLICY,trusted);
    reject(NULL,1,ENCBOUND_ERR_ENCODING,NULL);
    char *cap=encbound_malloc(16); assert(cap);
    unsigned char *raw=(void *)encbound_require((uintptr_t)cap,16,ENCBOUND_ACCESS_READWRITE);
    raw[0]=0x42; args[0]=(char *)raw;
    reject(args,2,ENCBOUND_ERR_POLICY,raw);
    args[0]=cap; assert(call(args,1,0)==0x42);
#ifdef ENCBOUND_MAC27
    args[0]=(char *)((uintptr_t)cap ^ (UINT64_C(1)<<32));
    reject(args,2,ENCBOUND_ERR_TAG,raw);
#endif
    encbound_free(cap);
#endif
    puts("USER_CHECK NATIVE BRIDGE/INSTRUMENTED-ACCESS PASS");
}
''')
flags = ['-I' + str(p) for p in (SDK / 'include', ROOT / 'tests/fixtures/modified_bridge',
                                ROOT / 'include', ROOT / 'runtime', ROOT / 'sdk', ROOT / 'tests')]


def generate(source, dest, profile, success=True):
    cmd = [sys.executable, ROOT / 'tools/modified_bridge.py', '--edl', source,
           '--interface', OUT / 'interface.json', '--out-dir', dest,
           '--generator', GEN, '--profile', profile]
    cmd += ['--cflag=' + f for f in flags]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if (result.returncode == 0) != success:
        raise AssertionError(result.stdout + result.stderr)
    if not success:
        assert 'modified-bridge: FAIL:' in result.stderr
        assert not list(dest.glob('*_t.c'))
    return result


rows = []
for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    dest = OUT / profile
    generate(OUT / 'probe.edl', dest, profile)
    bridge = (dest / 'probe_t.c').read_text()
    assert '_tmp_argv' in bridge
    assert all(s not in bridge for s in ('_len_argv', '_in_argv', '_encbound_cap_argv'))
    manifest = json.loads((dest / 'boundary-manifest.json').read_text())
    assert manifest['user_check_ecalls'] == {'probe': ['argv']}
    obj = dest / 'app.o'
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_CODEGEN_OPT='-O2')
    subprocess.run([ROOT / 'tools/encbound-cc.sh', OUT / 'app.c', obj,
                    '-O2', '-fno-builtin', '-fno-common'], env=env, check=True)
    ir = obj.with_suffix('.checked.ll').read_text()
    assert ('call i64 @encbound_require' in ir) == (profile != 'BASELINE')
    cmd = ['clang-21', '-O2', '-g', '-I' + str(dest), *flags]
    if profile != 'BASELINE':
        cmd += ['-DENCBOUND_PROTECTED']
    if profile == 'MAC27':
        cmd += ['-DENCBOUND_MAC27']
    sources = [ROOT / 'tests/fake_platform.c', ROOT / 'sdk/boundary_support.c']
    sources += [ROOT / 'runtime' / f for f in ('siphash.c', 'runtime.c', 'capability.c',
                                              'allocator.c', 'allocations.c')]
    exe = dest / 'test'
    subprocess.run([*cmd, OUT / 'test.c', obj, *sources, '-o', exe], check=True)
    result = subprocess.run([exe], capture_output=True, text=True)
    (dest / 'execution.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    rows.append(dict(profile=profile, result='pass', mode='native fake platform, real runtime',
                     executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))

# BASELINE must preserve the installed Intel generator's exact output.
stock = OUT / 'stock'
stock.mkdir(exist_ok=True)
subprocess.run([SDK / 'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock,
                '--untrusted', '--untrusted-dir', stock, OUT / 'probe.edl'], check=True)
for name in ('probe_t.c', 'probe_t.h', 'probe_u.c', 'probe_u.h'):
    assert (stock / name).read_bytes() == (OUT / 'BASELINE' / name).read_bytes()

negatives = {
    'in': DECL.replace('[user_check]', '[user_check,in]'),
    'out': DECL.replace('[user_check]', '[user_check,out]'),
    'size': DECL.replace('[user_check]', '[user_check,size=expected]'),
    'string': DECL.replace('[user_check]', '[user_check,string]'),
    'scalar': DECL.replace('char **argv', 'int argv'),
    'value': DECL.replace('[user_check]', '[user_check=1]'),
    'unknown_type': DECL.replace('char **argv', 'opaque *argv'),
}
for name, decl in negatives.items():
    source = OUT / (name + '.edl')
    source.write_text('enclave { trusted { ' + decl + ' }; };\n')
    generate(source, OUT / ('reject-' + name), 'MAC27', success=False)
source = OUT / 'ocall.edl'
source.write_text('enclave { trusted { public int enter(); }; untrusted { int host([user_check] char **p); }; };\n')
generate(source, OUT / 'accept-ocall', 'MAC27')
manifest = json.loads((OUT / 'accept-ocall/boundary-manifest.json').read_text())
assert manifest['user_check_ocalls'] == {'host': ['p']}
(OUT / 'results.json').write_text(json.dumps(dict(rows=rows, admission_negatives=len(negatives),
                                               baseline_matches_stock=True), indent=2) + '\n')
print('USER_CHECK PASS:', len(rows), 'native profiles,', len(negatives), 'admission negatives, OCALL admission, stock match')
