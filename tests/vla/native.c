#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/wait.h>
#include <unistd.h>
#include "encbound_platform.h"
#include "encbound_runtime.h"
#include "fake_platform.h"
extern int vla_run(size_t,int);
extern int vla_grid(size_t,size_t);
extern int vla_cpp(size_t);
extern int vla_cpp_signed(long,long),vla_signed_cases(long,long);
extern int vla_signed_direct(long,long),vla_signed_stored(long,long);
extern int vla_signed_scaled(long,long),vla_signed_shifted(long,long);
extern int vla_signed32(int,int),vla_unsigned32(unsigned,unsigned);
extern int vla_unsigned(unsigned long,unsigned long);
extern uintptr_t vla_last_raw;
extern unsigned vla_observations;
static ucontext_t caller,app;
static size_t count;
static int mode,result;
static unsigned destroyed;
void vla_destroyed(int value) { assert(value==7); ++destroyed; }
static void enter(void) {
    switch(mode) {
    case 8: result=vla_signed_cases(-2,-3); break;
    case 9: result=vla_signed_cases(-17,-19); break;
    case 10:result=vla_cpp_signed(-2,-3); break;
    case 11:result=vla_signed_direct(-2,3); break;
    case 12:result=vla_signed_stored(0,-3); break;
    case 13:result=vla_signed_direct(-((1L<<62)+1),-4); break;
    case 14:result=vla_signed_stored(-((1L<<62)+1),-4); break;
    case 15:result=vla_signed32(0x40000001,4); break;
    case 16:result=vla_unsigned32(0x80000001u,2); break;
    case 17:result=vla_unsigned(SIZE_MAX-1,SIZE_MAX-2); break;
    case 18:result=vla_signed_shifted((1L<<62)+1,1); break;
    case 19:result=vla_signed_scaled((1L<<62)+1,1); break;
    default:result=mode==7 ? vla_cpp(count) : mode==6 ? vla_grid(count,3) : vla_run(count,mode);
    }
}
static void execute(void) {
    assert(getcontext(&app)==0);
    app.uc_stack.ss_sp=(void *)(encbound_enclave_base()+0x100000);
    app.uc_stack.ss_size=0x100000;
    app.uc_link=&caller;
    makecontext(&app,enter,0);
    assert(swapcontext(&caller,&app)==0);
}
int main(void) {
    assert(encbound_runtime_init_with_key(11,22)==0);
    for (unsigned i=0;i<3;++i) {
        count=(size_t[]){17,33,129}[i]; mode=0;execute();
        if (result) fprintf(stderr,"VLA result %d, observations %u\n",result,vla_observations);
        assert(result==0);
        mode=7;destroyed=0;execute();assert(result==(int)(7*count) && destroyed==count);
    }
    mode=8;execute();assert(result==0);
    mode=9;execute();assert(result==0);
    mode=10;destroyed=0;execute();assert(result==42 && destroyed==6);
    unsigned controls=0;
#ifdef PROTECTED
    for (unsigned c=1;c<=19;++c) {
        if (c>=7 && c<=10) continue;
#ifndef ENCBOUND_MAC27
        if (c==5) continue;
#endif
        ++controls;
        pid_t child=fork();assert(child>=0);
        if (!child) {
            mode=(int)c;
            count=c==1 ? 0 : c==2 ? SIZE_MAX/4+1 : c==3 ? (1ul<<28) : c==6 ? SIZE_MAX/3+1 : 5;
            unsigned before=vla_observations;
            fake_abort_active=1;
            if (!setjmp(fake_abort_env)) {execute();_exit(91);}
            int expected=c<4 || c==6 || c>=11 ? ENCBOUND_ERR_ALLOC : c==4 ? ENCBOUND_ERR_RANGE : ENCBOUND_ERR_TAG;
            if (fake_abort_code!=expected) {fprintf(stderr,"control %u code %d\n",c,fake_abort_code);_exit(92);}
            if ((c<4 || c==6 || c>=11) && vla_observations!=before) _exit(93);
            if (c==4 && ((unsigned char *)vla_last_raw)[31]!=0x5a) _exit(94);
            _exit(0);
        }
        int status;assert(waitpid(child,&status,0)==child);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) fprintf(stderr,"control %u status %d\n",c,status);
        assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
    }
#endif
    printf("VLA NATIVE PASS: %u observations, %u attributed controls\n",vla_observations,controls);
    return 0;
}
