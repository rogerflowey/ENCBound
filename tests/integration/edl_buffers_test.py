#!/usr/bin/env python3
"""Intel's shared byte ranges and strings with real application instrumentation.

Native fake-platform execution on its modeled application stack; no SGX claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path(os.environ.get('SGX_SDK', str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--application-imports', action='store_true',
                    help='Exercise the same bridges through an application EDL import, with the full preset')
args = parser.parse_args()
BUILD = ROOT/'build/integration'/('edl-imports-execution' if args.application_imports else 'edl-buffers')
BUILD.mkdir(parents=True, exist_ok=True)
commands, rows = [], []


def run(command, name, env=None, success=True):
    command = list(map(str, command))
    p = subprocess.run(command, text=True, capture_output=True, env=env, timeout=120)
    log = BUILD/(name+'.log')
    log.write_text(p.stdout+p.stderr)
    commands.append(dict(command=command, returncode=p.returncode, log=str(log)))
    assert (p.returncode == 0) == success, (name, log.read_text())
    return p


(BUILD/'types.h').write_text('''#ifndef BUFFER_TYPES_H
#define BUFFER_TYPES_H
#include <stdint.h>
typedef int IntArray[3];
typedef int *IntPtr;
typedef void *VoidPtr;
typedef int64_t ScalarAlias;
typedef enum Flag { FlagYes=1 } Flag;
union Payload { uint32_t number; unsigned char bytes[4]; };
typedef struct __attribute__((packed)) Flat { Flag flag; union Payload payload; } Flat;
#endif
''')
buffer_params = '''[in,out,size=width,count=n] char *bytes, int width, int n,
 [in,out] int matrix[2][3], [in,out,isary] IntArray alias,
 [in,out,isptr,count=2] IntPtr pointer, [in,out] struct Local *local,
 [in,out] Flat *flat, ScalarAlias scale, enum Mode mode'''
string_params = '''[in,string] const char *input, [in,out,string] char *text,
 [in,wstring] const wchar_t *wide_input, [in,out,wstring] wchar_t *wide'''
(BUILD/'buffers.edl').write_text('''enclave {
 include "types.h"
 struct Local { uint32_t number; uint8_t bytes[3]; };
 enum Mode { ModeOne=1 };
 trusted {
  public int buffers('''+buffer_params+''');
  public int strings('''+string_params+''');
  public int extent([in,isptr,size=width,count=n] VoidPtr p, size_t width, int n);
  public void noop();
 };
 untrusted {
  int observe('''+buffer_params+''');
  int observe_strings('''+string_params+''');
  void observe_extent([in,isptr,size=width,count=n] VoidPtr p, size_t width, int n);
  void observe_noop();
 };
};
''')
api_edl = BUILD/'buffers.edl'
if args.application_imports:
    api_edl = BUILD/'buffer_api.edl'
    api_edl.write_text((BUILD/'buffers.edl').read_text())
    (BUILD/'buffers.edl').write_text('enclave { from "buffer_api.edl" import *; };\n')
(BUILD/'interface.json').write_text('{"records":{},"sdk_only_imports":{}}\n')
(BUILD/'application.c').write_text(r'''
#include "buffers_t.h"
int buffers(char *bytes,int width,int n,int matrix[2][3],IntArray alias,
            IntPtr pointer,struct Local *local,Flat *flat,ScalarAlias scale,enum Mode mode) {
    if(width!=2 || n!=4 || bytes[7]!='7' || matrix[1][2]!=6 || alias[2]!=9 ||
       pointer[1]!=11 || local->number!=12 || flat->payload.number!=13 || scale!=-7 || mode!=ModeOne) return -1;
    int result=0;
    if(observe(&result,bytes,width,n,matrix,alias,pointer,local,flat,scale,mode)!=SGX_SUCCESS || result!=23) return -2;
    if(bytes[0]!='!' || matrix[1][2]!=16 || alias[2]!=19 || pointer[1]!=21 ||
       local->number!=22 || flat->payload.number!=23) return -3;
    bytes[7]='?';return 42;
}
int strings(const char *input,char *text,const wchar_t *wide_input,wchar_t *wide) {
    if(input[0]!='i' || input[2]!=0 || text[0]!='t' || text[4]!=0 ||
       wide_input[0]!=L'i' || wide_input[2]!=0 || wide[0]!=L'w' || wide[4]!=0) return -1;
    int result=0;
    if(observe_strings(&result,input,text,wide_input,wide)!=SGX_SUCCESS || result!=31) return -2;
    if(text[0]!='x' || text[1]!=0 || wide[0]!=L'y' || wide[1]!=0) return -3;
    text[0]='a';wide[0]=L'b';return 43;
}
int extent(VoidPtr p,size_t width,int n) {
    if(!p && (width==0 || n==0))return 44;
    return p && width==4 && n==1 && ((char*)p)[0]=='q' ? 45 : -1;
}
void noop(void) { observe_noop(); }
''')
(BUILD/'harness.c').write_text(r'''
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "boundary_support.h"
#include "fake_platform.h"
int bridge_copy_fail;
#include "buffers_t.c"
static ucontext_t caller,application;
static sgx_status_t status;
static ms_buffers_t request;
static ms_strings_t strings_request;
static ms_extent_t extent_request;
static unsigned mode,observations,noops,direct,controls,copy_failures;
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
int sgx_is_outside_enclave(const void *p,size_t n) { return p && encbound_is_outside_enclave(p,n); }
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
    ++observations;
    if(index==0) {
        ms_observe_t *m=data;
        assert(m->ms_width==2 && m->ms_n==4 && !memcmp(m->ms_bytes,"01234567",8));
        assert(m->ms_matrix[5]==6 && (*m->ms_alias)[2]==9 && m->ms_pointer[1]==11);
        assert(m->ms_local->number==12 && m->ms_flat->payload.number==13 && m->ms_scale==-7 && m->ms_mode==ModeOne);
        m->ms_bytes[0]='!';m->ms_matrix[5]=16;(*m->ms_alias)[2]=19;m->ms_pointer[1]=21;
        m->ms_local->number=22;m->ms_flat->payload.number=23;m->ms_retval=23;
    } else if(index==1) {
        ms_observe_strings_t *m=data;
        if(direct) {
            assert(!m->ms_input && !m->ms_wide_input);
            if(m->ms_text)assert(!*m->ms_text);
            if(m->ms_wide)assert(!*m->ms_wide);
        } else {
            assert(!strcmp(m->ms_input,"in") && !strcmp(m->ms_text,"text"));
            assert(!wcscmp(m->ms_wide_input,L"in") && !wcscmp(m->ms_wide,L"wide"));
            memcpy(m->ms_text,"x\0ZZ",5);wmemcpy(m->ms_wide,L"y\0ZZ",5);
        }
        m->ms_retval=31;
    } else if(index==2) {
        ms_observe_extent_t *m=data;
        if(m->ms_width==4 && m->ms_n==1)assert(((char*)m->ms_p)[0]=='q');
        else assert(m->ms_width*(size_t)m->ms_n==0);
    } else {
        assert(index==3 && !data);++noops;
#ifdef ENCBOUND_PROTECTED
        assert(sgx_noop(NULL)==SGX_ERROR_ECALL_NOT_ALLOWED);
#endif
    }
    return SGX_SUCCESS;
}
static void enter(void) {
    if(mode==0)status=sgx_buffers(&request);
    else if(mode==1)status=sgx_strings(&strings_request);
    else if(mode==2)status=sgx_extent(&extent_request);
    else status=sgx_noop(NULL);
}
static void execute(void) {
    assert(getcontext(&application)==0);
    application.uc_stack.ss_sp=(void *)(encbound_enclave_base()+0x100000);
    application.uc_stack.ss_size=0x100000;application.uc_link=&caller;
    makecontext(&application,enter,0);assert(swapcontext(&caller,&application)==0);
}
int main(void) {
    assert(encbound_runtime_init_with_key(11,22)==0);
    char bytes[]="01234567";int matrix[2][3]={{1,2,3},{4,5,6}},alias[3]={7,8,9},pointer[2]={10,11};
    Local local={.number=12};Flat flat={.flag=FlagYes,.payload.number=13};
    request=(ms_buffers_t){.ms_bytes=bytes,.ms_width=2,.ms_n=4,.ms_matrix=(int*)matrix,
      .ms_alias=(IntArray*)alias,.ms_pointer=pointer,.ms_local=&local,.ms_flat=&flat,.ms_scale=-7,.ms_mode=ModeOne};
    char input[]="in",text[]="text";wchar_t wide_input[]=L"in",wide[]=L"wide";
    strings_request=(ms_strings_t){.ms_input=input,.ms_input_len=sizeof(input),.ms_text=text,.ms_text_len=sizeof(text),
      .ms_wide_input=wide_input,.ms_wide_input_len=sizeof(wide_input),.ms_wide=wide,.ms_wide_len=sizeof(wide)};
    mode=3;execute();assert(status==SGX_SUCCESS && noops==1);
    mode=0;execute();assert(status==SGX_SUCCESS && request.ms_retval==42);
    assert(!memcmp(bytes,"!123456?",8) && matrix[1][2]==16 && alias[2]==19 && pointer[1]==21 && local.number==22 && flat.payload.number==23);
    mode=1;execute();assert(status==SGX_SUCCESS && strings_request.ms_retval==43);
    assert(!memcmp(text,"a\0xt",5) && !wmemcmp(wide,L"b\0de",5));
    assert(!strcmp(input,"in") && !wcscmp(wide_input,L"in"));
    /* Intel rejects embedded NUL/misaligned wide lengths, then accepts recovery. */
    strings_request.ms_input_len=1;execute();assert(status==SGX_ERROR_UNEXPECTED);
    strings_request.ms_input_len=sizeof(input);strings_request.ms_wide_input_len=sizeof(wide_input)-1;
    execute();assert(status==SGX_ERROR_UNEXPECTED);
    mode=2;extent_request=(ms_extent_t){.ms_p=NULL,.ms_width=0,.ms_n=-1};
    execute();assert(status==SGX_SUCCESS && extent_request.ms_retval==44);
    extent_request.ms_width=2;execute();assert(status==SGX_ERROR_INVALID_PARAMETER);
    extent_request.ms_n=0;execute();assert(status==SGX_SUCCESS && extent_request.ms_retval==44);
    char opaque[4]={'q',0,0,0};extent_request=(ms_extent_t){.ms_p=opaque,.ms_width=4,.ms_n=1};
    execute();assert(status==SGX_SUCCESS && extent_request.ms_retval==45);
#ifdef ENCBOUND_PROTECTED
    assert(!live);
    /* Fail each ordinary buffer allocation and every string allocation. */
    memcpy(text,"text",5);wmemcpy(wide,L"wide",5);
    strings_request.ms_wide_input_len=sizeof(wide_input);
    for(unsigned c=0;c<2;++c) {
        mode=c;
        for(unsigned i=1;i<=(c?4:6);++i) {
            attempts=0;fail_at=i;execute();assert(status==SGX_ERROR_OUT_OF_MEMORY && !live);
        }
        fail_at=0;
    }
    mode=1;execute();assert(status==SGX_SUCCESS && strings_request.ms_retval==43 && !live);
    memcpy(text,"text",5);wmemcpy(wide,L"wide",5);
    bridge_copy_fail=1000;execute();copy_failures=1000-bridge_copy_fail;bridge_copy_fail=0;
    assert(status==SGX_SUCCESS && copy_failures>10 && !live);
    for(unsigned i=1;i<=copy_failures;++i) {
        memcpy(text,"text",5);wmemcpy(wide,L"wide",5);
        bridge_copy_fail=i;execute();bridge_copy_fail=0;
        assert((status==SGX_ERROR_UNEXPECTED || (status==SGX_SUCCESS && strings_request.ms_retval==-2)) && !live && !transport);
        memcpy(text,"text",5);wmemcpy(wide,L"wide",5);
        execute();assert(status==SGX_SUCCESS && strings_request.ms_retval==43 && !live);
    }
    char *cap=encbound_malloc(16);char *raw=(void*)encbound_require((uintptr_t)cap,16,3);
    memset(raw,0,16);direct=1;
    raw[0]='q';assert(observe_extent(cap,4,1)==SGX_SUCCESS);raw[0]=0;
    assert(observe_strings(NULL,NULL,cap+15,NULL,(wchar_t*)(cap+12))==SGX_SUCCESS);
    assert(observe_strings(NULL,NULL,NULL,NULL,NULL)==SGX_SUCCESS);
    assert(observe_extent(cap+15,SIZE_MAX/2+1,2)==SGX_SUCCESS);
    assert(observe_extent(cap+15,0,-1)==SGX_SUCCESS);
    for(unsigned c=0;c<7;++c) {
#ifndef ENCBOUND_MAC27
        if(c==6)continue;
#endif
        pid_t child=fork();assert(child>=0);
        if(!child) {
            unsigned before=observations;fake_abort_active=1;
            if(!setjmp(fake_abort_env)) {
                if(c==0){memset(raw,'x',16);observe_strings(NULL,NULL,cap,NULL,NULL);}
                if(c==1)observe_strings(NULL,NULL,NULL,NULL,(wchar_t*)(cap+13));
                if(c==2){memset(raw,0x41,16);observe_strings(NULL,NULL,NULL,NULL,(wchar_t*)cap);}
                if(c==3)observe_extent(cap+14,2,2);
                if(c==4)observe_strings(NULL,NULL,(char*)encbound_enclave_base(),NULL,NULL);
                if(c==5)observe_strings(NULL,NULL,raw,NULL,NULL);
                if(c==6)observe_strings(NULL,NULL,(char*)((uintptr_t)cap^(UINT64_C(1)<<32)),NULL,NULL);
                _exit(90);
            }
            int expected=c<4?ENCBOUND_ERR_RANGE:c==6?ENCBOUND_ERR_TAG:ENCBOUND_ERR_POLICY;
            assert(fake_abort_code==expected && observations==before && !transport);_exit(0);
        }
        int s;assert(waitpid(child,&s,0)==child && WIFEXITED(s) && WEXITSTATUS(s)==0);++controls;
    }
    encbound_free(cap);
#endif
    printf("FLAT BUFFERS NATIVE PASS controls=%u copy_failures=%u\n",controls,copy_failures);return 0;
}
''')
flags = ['-I'+str(p) for p in (BUILD, SDK/'include', ROOT/'include', ROOT/'sdk', ROOT/'runtime', ROOT/'tests', ROOT/'tests/fixtures/modified_bridge')]
for profile in ('BASELINE', 'RADIX_ONLY', 'MAC27'):
    out = BUILD/profile
    run(['python3', ROOT/'tools/modified_bridge.py', '--edl', BUILD/'buffers.edl', '--interface', BUILD/'interface.json',
         '--generator', ROOT/'build/edger8r/sgx_edger8r', '--profile', profile, '--out-dir', out,
         '--search-path', BUILD,
         *['--cflag='+f for f in flags]], profile+'-generate')
    if args.application_imports:
        manifest = json.loads((out/'boundary-manifest.json').read_text())
        assert manifest['imports'][0]['domain'] == 'application'
        assert manifest['inputs'][str(api_edl)] == hashlib.sha256(api_edl.read_bytes()).hexdigest()
    admitted = out/'admitted.txt'
    admitted.write_text('buffers\nstrings\nextent\nnoop\n'+(out/'admitted-ocalls.txt').read_text())
    if profile == 'BASELINE':
        stock = BUILD/'stock';stock.mkdir(exist_ok=True)
        run([SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock, '--untrusted', '--untrusted-dir', stock,
             '--search-path', BUILD,
             BUILD/'buffers.edl'], 'stock')
        for suffix in ('_t.c', '_t.h', '_u.c', '_u.h'):
            assert (stock/('buffers'+suffix)).read_bytes() == (out/('buffers'+suffix)).read_bytes()
    for opt in ('O0', 'O2'):
        name = profile+'-'+opt
        obj = out/('application-'+opt+'.o')
        env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_ADMITTED=str(admitted), ENCBOUND_CODEGEN_OPT='-'+opt)
        prefix = [ROOT/'tools/with-integration-defaults.sh', 'env', 'ENCBOUND_CODEGEN_OPT=-'+opt] if args.application_imports else []
        run([*prefix, ROOT/'tools/encbound-cc.sh', BUILD/'application.c', obj, *flags, '-I'+str(out), '-'+opt, '-fno-builtin'], name+'-application', env)
        definitions = [] if profile=='BASELINE' else ['-DENCBOUND_PROTECTED']
        if profile=='MAC27':definitions+=['-DENCBOUND_MAC27']
        runtime = [ROOT/'runtime'/(n+'.c') for n in ('runtime','siphash','capability','allocator','allocations','adapters')]
        wrap = [] if profile=='BASELINE' else ['-Wl,--wrap=encbound_boundary_alloc','-Wl,--wrap=encbound_boundary_free']
        exe = out/('test-'+opt)
        run(['clang-21','-O1',*definitions,*flags,'-I'+str(out),BUILD/'harness.c',obj,
             ROOT/'tests/fake_platform.c',ROOT/'sdk/boundary_support.c',*runtime,*wrap,'-o',exe], name+'-link')
        execution = run([exe],name+'-execute')
        rows.append(dict(profile=profile,optimization=opt,result='pass',output=execution.stdout.strip(),
                         executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
# Copied pointer fields/arrays are shallow bytes. Scalar aliases and alignment
# still have real ABI/allocation requirements.
types = (BUILD/'types.h').read_text()
edl = api_edl.read_text()
for name, source in {
    'enum-pointer-scalar': types.replace('typedef int64_t ScalarAlias;', 'typedef enum Flag *ScalarAlias;'),
    'overaligned-buffer': types.replace('__attribute__((packed))', '__attribute__((aligned(32)))'),
}.items():
    (BUILD/'types.h').write_text(source)
    run(['python3', ROOT/'tools/modified_bridge.py', '--edl', BUILD/'buffers.edl', '--interface', BUILD/'interface.json',
         '--generator', ROOT/'build/edger8r/sgx_edger8r', '--profile', 'MAC27', '--out-dir', BUILD/('rejected-'+name),
         '--search-path', BUILD,
         *['--cflag='+f for f in flags]], name, success=False)
(BUILD/'types.h').write_text(types)
api_edl.write_text(edl.replace('char *bytes, int width', 'char *bytes, float width'))
run(['python3', ROOT/'tools/modified_bridge.py', '--edl', BUILD/'buffers.edl', '--interface', BUILD/'interface.json',
     '--generator', ROOT/'build/edger8r/sgx_edger8r', '--profile', 'MAC27', '--out-dir', BUILD/'rejected-float-extent',
     '--search-path', BUILD,
     *['--cflag='+f for f in flags]], 'float-extent', success=False)
api_edl.write_text(edl)
(BUILD/'results.json').write_text(json.dumps(dict(scope='native fake platform, instrumented application, real runtime',rows=rows,commands=commands),indent=2)+'\n')
print('IMPORTED EDL BUFFERS PASS:' if args.application_imports else 'FLAT EDL BUFFERS PASS:',len(rows),'native rows; shared extents, aliases/arrays/composites, char/wchar strings, cleanup, protection and stock equality')
