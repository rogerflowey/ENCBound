/* Native fake-platform integration: actual alternate stack, real runtime.
 * ucontext belongs only to this trusted test harness, never application code.
 */
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"

long test_variadics(unsigned char *, int);
long native_test_variadics(unsigned char *, int);
static ucontext_t caller, application;
static unsigned char *argument;
static int mode;
static long result;
static void enter(void) { result = test_variadics(argument, mode); }
static void execute(void) {
    assert(getcontext(&application) == 0);
    application.uc_stack.ss_sp = (void *)(encbound_enclave_base()+0x100000);
    application.uc_stack.ss_size = 0x100000;
    application.uc_link = &caller;
    makecontext(&application, enter, 0);
    assert(swapcontext(&caller,&application) == 0);
}
int main(void) {
    assert(encbound_runtime_init_with_key(11,22) == 0);
    unsigned char oracle = 11;
    assert(native_test_variadics(&oracle,0) == 127 && oracle == 12);
    unsigned char *raw = (void *)(encbound_enclave_base()+0x1000000);
#ifdef PROTECTED
    argument = encbound_malloc(16);
    raw = (void *)encbound_require((uintptr_t)argument,16,ENCBOUND_ACCESS_WRITE);
#else
    argument = raw;
#endif
    *raw=11; mode=0; execute();
    assert(result == 127 && *raw == oracle);
#ifdef PROTECTED
    unsigned controls=4;
#ifdef ENCBOUND_MAC27
    controls=5;
#endif
    for (unsigned c=1;c<=controls;++c) {
        pid_t child=fork(); assert(child>=0);
        if (!child) {
            argument=(void *)encbound_enclave_base();
            *argument=0x77; mode=(int)c;
            fake_abort_active=1;
            if (!setjmp(fake_abort_env)) { execute(); _exit(2); }
            int expected = c==4 ? ENCBOUND_ERR_RANGE : c==5 ? ENCBOUND_ERR_TAG : ENCBOUND_ERR_POLICY;
            if (fake_abort_code != expected || *argument != 0x77) {
                fprintf(stderr,"control %u: expected %d, observed %d, target %u\n",
                        c,expected,fake_abort_code,*argument);
                _exit(3);
            }
            _exit(0); /* terminal test interception; application never resumes */
        }
        int status; assert(waitpid(child,&status,0)==child);
        if (!WIFEXITED(status) || WEXITSTATUS(status)!=0)
            fprintf(stderr,"control %u: child status %d\n",c,status);
        assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
    }
#endif
    puts("PASS: transformed calls on protected stack, native oracle, terminal rejection controls");
    return 0;
}
