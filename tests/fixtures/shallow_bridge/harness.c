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
#include "shallow_t.c"
static ucontext_t caller,application;
static ms_exercise_t request;
static sgx_status_t status;
static void *transport;
static uintptr_t echoed;
static unsigned observations,controls;
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
void *sgx_ocalloc(size_t n) { assert(!transport);return transport=malloc(n); }
void sgx_ocfree(void) { free(transport);transport=NULL; }
sgx_status_t sgx_ocall(unsigned index,void *data) {
    ++observations;assert(index==0);
    ms_exchange_t *m=data;
    assert(m->ms_bytes==12 && m->ms_f->n==8 && m->ms_f->data[7]==18);
    assert(m->ms_s->host[0]=='A' && m->ms_s->token==UINT64_MAX);
    assert(m->ms_s->owned==m->ms_pointers[0] && (uintptr_t)m->ms_pointers[1]==UINT64_MAX);
    assert((uintptr_t)m->ms_cookie==(uintptr_t)request.ms_cookie);
    assert((uintptr_t)m->ms_array==(uintptr_t)request.ms_array);
    assert(((char *)m->ms_opaque)[3]=='D');
    /* Only the host pointer is dereferenced here. Capability/token fields are
     * compared/copied, without traversing or converting their bit patterns. */
    m->ms_s->host[0]='J';m->ms_f->data[7]=28;((char *)m->ms_opaque)[3]='!';
    m->ms_cookie[0]=17;(*m->ms_array)[2]=19;m->ms_pointers[1]=m->ms_s->owned;
    echoed=(uintptr_t)m->ms_s->owned;
    m->ms_retval=m->ms_s->owned;
    if(m->ms_action==1)m->ms_retval=(void *)encbound_enclave_base();
    if(m->ms_action==2)m->ms_retval=(void *)(echoed^(UINT64_C(1)<<32));
    return SGX_SUCCESS;
}
static void enter(void) { status=sgx_exercise(&request); }
static void execute(void) {
    assert(getcontext(&application)==0);
    application.uc_stack.ss_sp=(void *)(encbound_enclave_base()+0x100000);
    application.uc_stack.ss_size=0x100000;application.uc_link=&caller;
    makecontext(&application,enter,0);assert(swapcontext(&caller,&application)==0);
    assert(!transport);
}
static void reset(Flexible *f,Shallow *s,char **pointers,char *opaque,char *host,int *array) {
    f->n=8;for(unsigned i=0;i<8;++i)f->data[i]=i+1;
    host[0]='H';*s=(Shallow){host,(char *)UINT64_MAX,UINT64_MAX};
    pointers[0]=(char *)1;pointers[1]=(char *)UINT64_MAX;
    memcpy(opaque,"abcd",4);array[0]=7;array[1]=8;array[2]=9;
}
int main(void) {
    assert(encbound_runtime_init_with_key(11,22)==0);
    Flexible *f=malloc(12);Shallow s;char *pointers[2],opaque[4],host[1];int array[3];
    reset(f,&s,pointers,opaque,host,array);
    request=(ms_exercise_t){.ms_f=f,.ms_bytes=12,.ms_s=&s,.ms_pointers=pointers,
      .ms_opaque=(Opaque *)opaque,.ms_cookie=array,.ms_array=(IntArray *)array};
    execute();assert(status==SGX_SUCCESS && (uintptr_t)request.ms_retval==echoed && echoed>5);
    assert(host[0]=='J' && f->data[7]==28 && opaque[3]=='!' && array[0]==17 && array[2]==19);
    assert((uintptr_t)s.owned==echoed && (uintptr_t)pointers[0]==echoed && (uintptr_t)pointers[1]==echoed);
#ifdef ENCBOUND_PROTECTED
    for(unsigned action=1;action<=2;++action) {
#ifndef ENCBOUND_MAC27
        if(action==2)continue;
#endif
        reset(f,&s,pointers,opaque,host,array);request.ms_action=action;
        pid_t child=fork();assert(child>=0);
        if(!child) {
            unsigned before=observations;unsigned char *target=(void *)encbound_enclave_base();
            *target=0x31;fake_abort_active=1;
            if(!setjmp(fake_abort_env)){execute();_exit(90);}
            assert(fake_abort_code==(action==1?ENCBOUND_ERR_POLICY:ENCBOUND_ERR_TAG));
            assert(*target==0x31 && observations==before+1 && !transport);_exit(0);
        }
        int child_status;assert(waitpid(child,&child_status,0)==child &&
          WIFEXITED(child_status) && WEXITSTATUS(child_status)==0);++controls;
    }
    /* These newly admitted composite buffers retain the same full-range and
     * result-destination checks before any host call. */
    char *cap=encbound_malloc(16);char *raw=(void *)encbound_require((uintptr_t)cap,16,3);
    for(unsigned which=0;which<3;++which) {
        pid_t child=fork();assert(child>=0);
        if(!child) {
            unsigned before=observations;fake_abort_active=1;
            if(!setjmp(fake_abort_env)) {
                void *result=NULL;
                if(which==0)exchange(&result,(Flexible *)(cap+8),12,NULL,NULL,NULL,NULL,NULL,0);
                if(which==1)exchange(&result,(Flexible *)raw,12,NULL,NULL,NULL,NULL,NULL,0);
                if(which==2)exchange((void **)(cap+15),NULL,0,NULL,NULL,NULL,NULL,NULL,0);
                _exit(90);
            }
            assert(fake_abort_code==(which==1?ENCBOUND_ERR_POLICY:ENCBOUND_ERR_RANGE));
            assert(observations==before && !transport);_exit(0);
        }
        int child_status;assert(waitpid(child,&child_status,0)==child &&
          WIFEXITED(child_status) && WEXITSTATUS(child_status)==0);++controls;
    }
    encbound_free(cap);
#endif
    free(f);printf("SHALLOW BRIDGE NATIVE PASS controls=%u\n",controls);
}
