#!/usr/bin/env python3
"""OCALL pointer-value transport with instrumented app code and real checks.

Native fake platform on its modeled app stack; no SGX isolation claim.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
OUT = ROOT / 'build/integration/user-check-ocall'
OUT.mkdir(parents=True, exist_ok=True)
commands, rows = [], []


def run(command, name, env=None, success=True):
    command = list(map(str, command))
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    log = OUT / (name + '.log')
    log.write_text(result.stdout + result.stderr)
    commands.append(dict(command=command, returncode=result.returncode, log=str(log)))
    assert (result.returncode == 0) == success, log.read_text()
    return result


DECL = 'uintptr_t exchange([user_check] char **pointer, uintptr_t expected, int action, [in,out,size=8] char *buffer);'
EDL = '''enclave {
 trusted { public int exercise([user_check] char **host, int action, uintptr_t expected); };
 untrusted {
  ''' + DECL + '''
  void observe([user_check] const void *cookie);
 };
};
'''
(OUT / 'probe.edl').write_text(EDL)
(OUT / 'interface.json').write_text('{"records":{},"sdk_only_imports":{}}\n')
(OUT / 'application.c').write_text(r'''
#include <stdlib.h>
#include "probe_t.h"
int exercise(char **host, int action, uintptr_t expected) {
    char copied[8]="copy123";
    uintptr_t echo=0;
    if(action==4) return observe((const void *)host)==SGX_SUCCESS ? 44 : -4;
    char *owned=NULL;
    if(action==2) {
        owned=malloc(16);if(!owned)return -10;
        owned[0]='q';host=(char **)owned;expected=(uintptr_t)owned;
    }
    sgx_status_t status=exchange(&echo,host,expected,action,copied);
    if(status!=SGX_SUCCESS)return -1;
    if(echo!=expected || copied[0]!='!')return -2;
    if(action==1 && host[0][0]!='B')return -3;
    if(action==2) {
        char *same=(char *)echo;
        if(same[0]!='q')return -5;
        same[0]='r';if(owned[0]!='r')return -6;
        free(owned);
    }
    if(action==3) *(char *)echo='x'; /* hostile host-supplied result */
    return 42;
}
''')
(OUT / 'harness.c').write_text(r'''
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
int bridge_copy_fail;
#include "probe_t.c"
static ucontext_t caller,application;
static ms_exercise_t request;
static sgx_status_t status,transport_error;
static void *transport;
static unsigned observations,controls,copy_failures;
static int alloc_fail;
int sgx_is_outside_enclave(const void *p,size_t n) {
    return p && encbound_is_outside_enclave(p,n);
}
int sgx_is_within_enclave(const void *p,size_t n) {
#ifdef ENCBOUND_PROTECTED
    uintptr_t a=(uintptr_t)p,b=encbound_enclave_base();
    return a>=b && a-b<encbound_enclave_size() && n<=encbound_enclave_size()-(a-b);
#else
    (void)n;return p!=NULL;
#endif
}
void *sgx_ocalloc(size_t n) {
    assert(!transport);return alloc_fail ? NULL : (transport=malloc(n));
}
void sgx_ocfree(void) { free(transport);transport=NULL; }
sgx_status_t sgx_ocall(unsigned index,void *data) {
    ++observations;
    if(transport_error)return transport_error;
    if(index==1) {
        ms_observe_t *m=data;
        assert((uintptr_t)m->ms_cookie==request.ms_expected);
        return SGX_SUCCESS;
    }
    assert(index==0);
    ms_exchange_t *m=data;
    assert(!memcmp(m->ms_buffer,"copy123",8));
    assert(m->ms_action==3 || (uintptr_t)m->ms_pointer==m->ms_expected);
    if(m->ms_action==1) {
        m->ms_pointer[0][0]='h';m->ms_pointer[0]=m->ms_pointer[1];
    }
    /* A capability is compared/echoed, never dereferenced by the host. */
    m->ms_buffer[0]='!';m->ms_retval=m->ms_expected;
    return SGX_SUCCESS;
}
static void enter(void) {status=sgx_exercise(&request);}
static void execute(char **p,int action,uintptr_t expected) {
    request=(ms_exercise_t){.ms_host=p,.ms_action=action,.ms_expected=expected};
    assert(getcontext(&application)==0);
    application.uc_stack.ss_sp=(void *)(encbound_enclave_base()+0x100000);
    application.uc_stack.ss_size=0x100000;application.uc_link=&caller;
    makecontext(&application,enter,0);assert(swapcontext(&caller,&application)==0);
    assert(!transport);
}
#ifdef ENCBOUND_PROTECTED
static void reject(unsigned which,char **host,uintptr_t bad,char *buffer,
                   uintptr_t *retval,int code,unsigned char *target) {
    pid_t child=fork();assert(child>=0);
    if(!child) {
        unsigned before=observations;unsigned char byte=*target;
        fake_abort_active=1;
        if(!setjmp(fake_abort_env)) {
            if(which==0)execute(host,3,bad);
            else exchange(retval,host,(uintptr_t)host,0,buffer);
            _exit(90);
        }
        assert(fake_abort_code==code && *target==byte && !transport);
        assert(observations==before+(which==0));
        _exit(0); /* caught terminal abort never resumes a failed session */
    }
    int s;assert(waitpid(child,&s,0)==child && WIFEXITED(s) && WEXITSTATUS(s)==0);
    ++controls;
}
#endif
int main(void) {
    assert(encbound_runtime_init_with_key(11,22)==0);
    uintptr_t bits[]={0,1,UINT64_C(1)<<48,UINT64_MAX};
    for(unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i) {
        execute((char **)bits[i],0,bits[i]);
        assert(status==SGX_SUCCESS && request.ms_retval==42);
        execute((char **)bits[i],4,bits[i]);
        assert(status==SGX_SUCCESS && request.ms_retval==44);
    }
    char first[]="Abc",second[]="Bcd";char *host[]={first,second};
    execute(host,1,(uintptr_t)host);
    assert(status==SGX_SUCCESS && request.ms_retval==42 && first[0]=='h' && host[0]==second);
    execute(NULL,2,0);assert(status==SGX_SUCCESS && request.ms_retval==42);
#ifdef ENCBOUND_PROTECTED
    char *cap=encbound_malloc(16);uintptr_t *result=encbound_malloc(16);
    assert(cap && result);
    char *raw=(void *)encbound_require((uintptr_t)cap,16,3);
    uintptr_t *raw_result=(void *)encbound_require((uintptr_t)result,16,3);
#else
    char *cap=malloc(16);uintptr_t *result=malloc(16);assert(cap && result);
    char *raw=cap;uintptr_t *raw_result=result;
#endif
    memcpy(raw,"copy123",8);
#ifdef ENCBOUND_PROTECTED
    unsigned char *trusted=(void *)encbound_enclave_base();*trusted=0x31;
    /* Host return values get checked on the application's actual store. */
    reject(0,host,(uintptr_t)trusted,cap,result,ENCBOUND_ERR_POLICY,trusted);
    reject(0,host,(uintptr_t)raw,cap,result,ENCBOUND_ERR_POLICY,(unsigned char *)raw);
    /* Mixed copied arguments and the implicit result destination stay checked. */
    reject(1,host,0,raw,result,ENCBOUND_ERR_POLICY,(unsigned char *)raw);
    reject(1,host,0,(char *)trusted,result,ENCBOUND_ERR_POLICY,trusted);
    reject(1,host,0,cap+12,result,ENCBOUND_ERR_RANGE,(unsigned char *)raw);
    reject(1,host,0,cap,(uintptr_t *)trusted,ENCBOUND_ERR_POLICY,trusted);
    reject(1,host,0,cap,(uintptr_t *)((char *)result+15),ENCBOUND_ERR_RANGE,(unsigned char *)raw_result);
#ifdef ENCBOUND_MAC27
    uintptr_t corrupt=(uintptr_t)cap^(UINT64_C(1)<<32);
    reject(0,host,corrupt,cap,result,ENCBOUND_ERR_TAG,(unsigned char *)raw);
    reject(1,host,0,(char *)corrupt,result,ENCBOUND_ERR_TAG,(unsigned char *)raw);
#endif
#endif
    /* No extra policy on an unused user_check value, even a raw enclave address. */
    execute((char **)raw,0,(uintptr_t)raw);assert(status==SGX_SUCCESS && request.ms_retval==42);
    memcpy(raw,"copy123",8);
    unsigned before=observations;
    alloc_fail=1;
    assert(exchange(result,host,(uintptr_t)host,0,cap)==SGX_ERROR_UNEXPECTED);
    assert(observations==before && !transport);alloc_fail=0;
    transport_error=SGX_ERROR_UNEXPECTED;
    assert(exchange(result,host,(uintptr_t)host,0,cap)==SGX_ERROR_UNEXPECTED);
    assert(!transport);transport_error=SGX_SUCCESS;
    for(int n=1;n<20;++n) {
        memcpy(raw,"copy123",8);bridge_copy_fail=n;
        sgx_status_t s=exchange(result,host,(uintptr_t)host,0,cap);
        assert(!transport);
        if(s==SGX_SUCCESS) {assert(bridge_copy_fail>0 && n>1);break;}
        assert(s==SGX_ERROR_UNEXPECTED);++copy_failures;
        assert(n<19);
    }
    bridge_copy_fail=0;memcpy(raw,"copy123",8);
    assert(exchange(result,host,(uintptr_t)host,0,cap)==SGX_SUCCESS);
    assert(*raw_result==(uintptr_t)host && raw[0]=='!' && !transport);
#ifdef ENCBOUND_PROTECTED
    encbound_free(result);encbound_free(cap);
#else
    free(result);free(cap);
#endif
    printf("OCALL USER_CHECK NATIVE PASS controls=%u copy_failures=%u\n",controls,copy_failures);
}
''')
flags = ['-I' + str(p) for p in (SDK / 'include', ROOT / 'include', ROOT / 'sdk',
                                ROOT / 'runtime', ROOT / 'tests', ROOT / 'tests/fixtures/modified_bridge')]


def generate(source, out, profile, name, success=True):
    result = run(['python3', ROOT / 'tools/modified_bridge.py', '--edl', source,
                  '--interface', OUT / 'interface.json', '--generator', ROOT / 'build/edger8r/sgx_edger8r',
                  '--out-dir', out, '--profile', profile, *['--cflag=' + f for f in flags]], name, success=success)
    if not success:
        assert 'modified-bridge: FAIL:' in result.stderr
        assert not list(out.glob('*_t.c'))


for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    dest = OUT / profile
    generate(OUT / 'probe.edl', dest, profile, profile + '-generate')
    for file in ('boundary-manifest.json', 'edger8r-admission.json'):
        metadata = json.loads((dest / file).read_text())
        assert metadata['user_check_ecalls'] == {'exercise': ['host']}
        assert metadata['user_check_ocalls'] == {'exchange': ['pointer'], 'observe': ['cookie']}
    bridge = (dest / 'probe_t.c').read_text()
    assert '_len_pointer' not in bridge and '_len_cookie' not in bridge
    admitted = dest / 'admitted.txt'
    admitted.write_text('exercise\n' + (dest / 'admitted-ocalls.txt').read_text())
    for opt in ('O0', 'O2'):
        name = profile + '-' + opt
        obj = dest / ('application-' + opt + '.o')
        env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted), ENCBOUND_CODEGEN_OPT='-' + opt)
        run([ROOT / 'tools/encbound-cc.sh', OUT / 'application.c', obj, *flags, '-I' + str(dest),
             '-' + opt, '-fno-builtin', '-fno-common'], name + '-application', env)
        definitions = [] if profile == 'BASELINE' else ['-DENCBOUND_PROTECTED']
        if profile == 'MAC27':
            definitions += ['-DENCBOUND_MAC27']
        runtime = [ROOT / 'runtime' / (n + '.c') for n in ('runtime', 'siphash', 'capability', 'allocator', 'allocations')]
        exe = dest / ('test-' + opt)
        run(['clang-21', '-O1', *definitions, *flags, '-I' + str(dest), OUT / 'harness.c', obj,
             ROOT / 'tests/fake_platform.c', ROOT / 'sdk/boundary_support.c', *runtime, '-o', exe], name + '-link')
        result = run([exe], name + '-execute')
        rows.append(dict(profile=profile, optimization=opt, result='pass', output=result.stdout.strip(),
                         executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
stock = OUT / 'stock'
stock.mkdir(exist_ok=True)
run([SDK / 'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock, '--untrusted', '--untrusted-dir', stock,
     OUT / 'probe.edl'], 'stock')
for suffix in ('_t.c', '_t.h', '_u.c', '_u.h'):
    assert (stock / ('probe' + suffix)).read_bytes() == (OUT / 'BASELINE' / ('probe' + suffix)).read_bytes()

negatives = {
    'in': DECL.replace('[user_check]', '[user_check,in]'),
    'out': DECL.replace('[user_check]', '[user_check,out]'),
    'size': DECL.replace('[user_check]', '[user_check,size=expected]'),
    'count': DECL.replace('[user_check]', '[user_check,count=expected]'),
    'string': DECL.replace('[user_check]', '[user_check,string]'),
    'isptr': DECL.replace('[user_check]', '[user_check,isptr]'),
    'isary': DECL.replace('[user_check]', '[user_check,isary]'),
    'scalar': DECL.replace('char **pointer', 'int pointer'),
    'value': DECL.replace('[user_check]', '[user_check=1]'),
    'unknown': DECL.replace('char **pointer', 'Unknown *pointer'),
}
for name, declaration in negatives.items():
    source = OUT / (name + '.edl')
    source.write_text(EDL.replace(DECL, declaration))
    generate(source, OUT / ('reject-' + name), 'MAC27', 'reject-' + name, success=False)
(OUT / 'results.json').write_text(json.dumps(dict(scope='native fake platform, real runtime, instrumented application',
    rows=rows, commands=commands, admission_negatives=len(negatives), baseline_matches_stock=True), indent=2) + '\n')
print('OCALL USER_CHECK PASS:', len(rows), 'native rows,', len(negatives), 'admission negatives; stock equality')
