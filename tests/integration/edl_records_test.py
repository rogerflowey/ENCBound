#!/usr/bin/env python3
"""Generated record adapters: real instrumentation, native ABI and failure paths.

The harness is trusted, uses the fake platform and executes on its real modeled
application stack. No SGX/hardware result is implied by these native tests.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
BUILD = ROOT/'build/integration/edl-records'
BUILD.mkdir(parents=True, exist_ok=True)
commands, rows = [], []

def run(command, name, env=None, success=True):
    command = list(map(str, command))
    p = subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)
    log = BUILD/(name+'.log')
    log.write_text(p.stdout+p.stderr)
    commands.append(dict(command=command, returncode=p.returncode, log=str(log)))
    assert (p.returncode == 0) == success, (name, log.read_text())
    return p

(BUILD/'types.h').write_text('''#include <stdint.h>
typedef struct Small { uint64_t a, b; } Small;
typedef struct Big { uint64_t words[5]; Small nested; double ratio; } Big;
''')
parameters = 'uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, Small small, Big first, Big second'
(BUILD/'records.edl').write_text('''enclave {
 include "types.h"
 trusted {
  public int record_run('''+parameters+''', [out] uint64_t *output);
  public void record_void(Big value);
 };
 untrusted {
  int record_emit('''+parameters+''');
  void record_emit_void(Big value);
 };
};
''')
(BUILD/'interface.json').write_text(json.dumps(dict(sdk_only_imports={}, records={n:dict(header='types.h') for n in ('Small','Big')})))
(BUILD/'application.c').write_text(r'''
#include "records_t.h"
int record_run(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,
               Small small,Big first,Big second,uint64_t *output) {
    if(a+b+c+d+e+f!=21 || small.a!=7 || small.b!=8 ||
       first.words[0]!=11 || second.words[0]!=22 ||
       first.nested.a!=31 || second.nested.a!=32 ||
       first.ratio!=1.25 || second.ratio!=2.5) return -1;
    first.words[0]+=100;small.a+=10;
    int observed=0;
    if(record_emit(&observed,a,b,c,d,e,f,small,first,second)!=SGX_SUCCESS || observed!=133) return -2;
    if(first.words[0]!=111 || small.a!=17 || second.words[0]!=22) return -3;
    *output=first.words[0]+second.words[0];return 42;
}
void record_void(Big value) { value.words[0]+=100;record_emit_void(value); }
''')
(BUILD/'harness.c').write_text(r'''
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
#include "records_t.c"
static ucontext_t caller,application;
static sgx_status_t status;
static ms_record_run_t request;
static ms_record_void_t void_request;
static uint64_t output;
static unsigned mode,observations,void_observations;
static void *transport;
#ifdef ENCBOUND_PROTECTED
static unsigned attempts,fail_at,live;
void *__real_encbound_boundary_alloc(size_t);
void __real_encbound_boundary_free(void *);
void *__wrap_encbound_boundary_alloc(size_t n) {
    if(++attempts==fail_at)return NULL;
    void *p=__real_encbound_boundary_alloc(n);if(p)++live;return p;
}
void __wrap_encbound_boundary_free(void *p) {if(p){assert(live);--live;}__real_encbound_boundary_free(p);}
#endif
int sgx_is_outside_enclave(const void *p,size_t n) {(void)n;return p!=NULL;}
int sgx_is_within_enclave(const void *p,size_t n) {
#ifdef ENCBOUND_PROTECTED
    uintptr_t a=(uintptr_t)p,b=encbound_enclave_base();
    return a>=b && a-b<encbound_enclave_size() && n<=encbound_enclave_size()-(a-b);
#else
    (void)n;return p!=NULL;
#endif
}
void *sgx_ocalloc(size_t n){assert(!transport);return transport=malloc(n);}
void sgx_ocfree(void){free(transport);transport=NULL;}
sgx_status_t sgx_ocall(unsigned index,void *data) {
    if(index==0){
        ms_record_emit_t *m=data;
        assert(m->ms_a+m->ms_b+m->ms_c+m->ms_d+m->ms_e+m->ms_f==21);
        assert(m->ms_small.a==17 && m->ms_small.b==8);
        assert(m->ms_first.words[0]==111 && m->ms_second.words[0]==22);
        assert(m->ms_first.nested.a==31 && m->ms_second.ratio==2.5);
        m->ms_retval=133;m->ms_first.words[0]=999;m->ms_small.a=999;++observations;
    }else{
        ms_record_emit_void_t *m=data;assert(index==1 && m->ms_value.words[0]==111);++void_observations;
    }
    return SGX_SUCCESS;
}
static void enter(void){
    if(mode==0)status=sgx_record_run(&request);
    else if(mode==1)status=sgx_record_void(&void_request);
#ifdef ENCBOUND_PROTECTED
    else {
        const Big *p=(const Big *)encbound_enclave_base();
        if(mode==3 || mode==4){
            Big *cap=encbound_malloc(sizeof(Big));assert(cap);
            p=mode==3?(const Big *)((uintptr_t)cap+8):(const Big *)((uintptr_t)cap^(UINT64_C(1)<<32));
        }
        if(mode==5)__encbound_edl_proxy_record_emit_void(p);
        else __encbound_edl_app_record_void(p);
    }
#endif
}
static void execute(void){
    assert(getcontext(&application)==0);
    application.uc_stack.ss_sp=(void *)(encbound_enclave_base()+0x100000);
    application.uc_stack.ss_size=0x100000;application.uc_link=&caller;
    makecontext(&application,enter,0);assert(swapcontext(&caller,&application)==0);
}
int main(void){
    int copy_failures=0;
    _Static_assert(sizeof(Big)==64,"large record");
    _Static_assert(sizeof(Small)==16,"register-exhausted small record");
    assert(encbound_runtime_init_with_key(11,22)==0);
    request=(ms_record_run_t){.ms_a=1,.ms_b=2,.ms_c=3,.ms_d=4,.ms_e=5,.ms_f=6,
      .ms_small={7,8},.ms_first={.words={11},.nested={31,41},.ratio=1.25},
      .ms_second={.words={22},.nested={32,42},.ratio=2.5},.ms_output=&output};
    void_request.ms_value=request.ms_first;
    fake_abort_active=1;
    if(setjmp(fake_abort_env)){fprintf(stderr,"unexpected rejection %d\n",fake_abort_code);return 1;}
    for(unsigned i=0;i<8;++i){
        mode=0;output=0;execute();assert(status==SGX_SUCCESS && request.ms_retval==42 && output==133);
        assert(request.ms_first.words[0]==11 && request.ms_second.words[0]==22 && request.ms_small.a==7);
        mode=1;execute();assert(status==SGX_SUCCESS && void_request.ms_value.words[0]==11);
    }
#ifdef ENCBOUND_PROTECTED
    assert(!live);
    for(unsigned i=1;i<=4;++i){
        mode=0;attempts=0;fail_at=i;output=777;unsigned before=observations;
        execute();assert(status==SGX_ERROR_OUT_OF_MEMORY && !live && observations==before && output==777);
        fail_at=0;execute();assert(status==SGX_SUCCESS && request.ms_retval==42 && !live);
    }
    /* Snapshot, each record import, and result/output copies: fail every copy
     * reached on a successful call and verify recoverable cleanup each time. */
    mode=0;bridge_copy_fail=1000;execute();copy_failures=1000-bridge_copy_fail;bridge_copy_fail=0;
    assert(status==SGX_SUCCESS && copy_failures>=14);
    for(int i=1;i<=copy_failures;++i){
        mode=0;bridge_copy_fail=i;execute();bridge_copy_fail=0;
        /* An OCALL copy error is reported to the app, which returns -2;
         * ECALL copies instead report the Intel transport error directly. */
        assert((status==SGX_ERROR_UNEXPECTED || (status==SGX_SUCCESS && request.ms_retval==-2)) && !live && !transport);
        execute();assert(status==SGX_SUCCESS && request.ms_retval==42 && !live);
    }
    for(unsigned c=2;c<=5;++c){
#ifndef ENCBOUND_MAC27
        if(c==4)continue;
#endif
        pid_t child=fork();assert(child>=0);
        if(!child){
            mode=c;output=777;unsigned before=void_observations;fake_abort_active=1;
            if(!setjmp(fake_abort_env)){execute();_exit(90);}
            int want=c==3?ENCBOUND_ERR_RANGE:c==4?ENCBOUND_ERR_TAG:ENCBOUND_ERR_POLICY;
            assert(fake_abort_code==want && output==777 && void_observations==before && !transport);_exit(0);
        }
        int s;assert(waitpid(child,&s,0)==child && WIFEXITED(s) && WEXITSTATUS(s)==0);
    }
#endif
    printf("GENERATED RECORD ADAPTER NATIVE PASS copy_failures=%d\n",copy_failures);return 0;
}
''')

flags = ['-I'+str(p) for p in (BUILD, SDK/'include', ROOT/'include', ROOT/'sdk', ROOT/'runtime', ROOT/'tests', ROOT/'tests/fixtures/modified_bridge')]
for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    generated = BUILD/profile
    run(['python3', ROOT/'tools/modified_bridge.py', '--wide-scalars', '--edl', BUILD/'records.edl',
         '--interface', BUILD/'interface.json', '--generator', ROOT/'build/edger8r/sgx_edger8r',
         '--profile', profile, '--out-dir', generated, *['--cflag='+f for f in flags]], profile+'-generate')
    native = json.loads((generated/'edger8r-admission.json').read_text())
    admitted = generated/'admitted.txt'
    admitted.write_text('record_run\nrecord_void\n'+(generated/'admitted-ocalls.txt').read_text()+(generated/'admitted-app.txt').read_text())
    if profile == 'BASELINE':
        stock = BUILD/'stock';stock.mkdir(exist_ok=True)
        run([SDK/'bin/x64/sgx_edger8r','--trusted','--trusted-dir',stock,'--untrusted','--untrusted-dir',stock,BUILD/'records.edl'], 'stock')
        for suffix in ('_t.c','_t.h','_u.c','_u.h'):
            assert (stock/('records'+suffix)).read_bytes() == (generated/('records'+suffix)).read_bytes()
    else:
        assert native['record_ecalls']==['record_run','record_void']
        assert native['record_ocalls']==['record_emit','record_emit_void']
    for opt in ('O0','O2'):
        name=profile+'-'+opt;directory=BUILD/name;directory.mkdir(exist_ok=True)
        env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_AGGREGATE_ABI='1',ENCBOUND_ADMITTED=str(admitted),ENCBOUND_CODEGEN_OPT='-'+opt)
        objects=[]
        for source in (BUILD/'application.c', generated/'records_app.c'):
            obj=directory/(source.stem+'.o');objects.append(obj)
            run([ROOT/'tools/encbound-cc.sh',source,obj,*flags,'-I'+str(generated),'-'+opt,'-fno-builtin'],name+'-'+source.stem,env)
            ir=obj.with_suffix('.checked.ll').read_text()
            if profile!='BASELINE':
                assert not re.search(r'\b(?:byval|sret)\(',ir)
                assert '__encbound_abi_' in ir
                if source.name=='records_app.c':assert not re.search(r'\btail call\b',ir)
        definitions=[]
        if profile!='BASELINE':definitions+=['-DENCBOUND_PROTECTED']
        if profile=='MAC27':definitions+=['-DENCBOUND_MAC27']
        runtime=[ROOT/'runtime'/(n+'.c') for n in ('runtime','siphash','capability','allocator','allocations','adapters')]
        exe=directory/'test'
        wrap=[] if profile=='BASELINE' else ['-Wl,--wrap=encbound_boundary_alloc','-Wl,--wrap=encbound_boundary_free']
        run(['clang-21','-O1',*definitions,*flags,'-I'+str(generated),BUILD/'harness.c',*objects,
             ROOT/'tests/fake_platform.c',ROOT/'sdk/boundary_support.c',*runtime,*wrap,'-o',exe],name+'-link')
        execution=run([exe],name+'-execute')
        copy_failures=int(re.search(r'copy_failures=(\d+)',execution.stdout)[1])
        if profile!='BASELINE':
            p=run(['clang-21','-O1',*definitions,*flags,'-I'+str(generated),BUILD/'harness.c',objects[0],
                   ROOT/'tests/fake_platform.c',ROOT/'sdk/boundary_support.c',*runtime,*wrap,'-o',directory/'missing-adapter'],name+'-missing-adapter',success=False)
            assert '__encbound_edl_app_' in p.stderr
        rows.append(dict(profile=profile,optimization=opt,result='pass',native_calls=16,
                         allocation_failures=0 if profile=='BASELINE' else 4,
                         copy_failures=copy_failures,
                         protection_controls=0 if profile=='BASELINE' else 4 if profile=='MAC27' else 3,
                         executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
(BUILD/'results.json').write_text(json.dumps(dict(scope='native fake platform, real runtime and application stack',rows=rows,commands=commands),indent=2)+'\n')
print('GENERATED EDL RECORDS PASS:',len(rows),'native rows; large/multiple/register-exhausted values, void calls, checked adapters, cleanup and stock equality')
