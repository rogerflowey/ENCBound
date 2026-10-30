/* Real checked runtime and pinned SDK guards; registration transport spy only.
 * Native platform is synthetic, with no SGX isolation claim. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "encbound_runtime.h"
#include "fake_platform.h"
extern int encbound_cxx_atexit(void (*)(void *),void *);
extern int encbound_cxx_guard_acquire(void *);
extern void encbound_cxx_guard_release(void *),encbound_cxx_guard_abort(void *);
extern void *__dso_handle;
static void (*registered)(void *);
static void *argument,*token;
static int registration_result;
int __wrap___cxa_atexit(void (*f)(void *),void *p,void *dso) {
    registered=f;argument=p;token=dso;return registration_result;
}
static void callback(void *p) { assert(p==argument); }
int main(void) {
    assert(encbound_runtime_init_with_key(11,22)==0);
    void *guard=encbound_calloc(1,8);assert(guard);
    uintptr_t raw=encbound_require((uintptr_t)guard,8,ENCBOUND_ACCESS_READWRITE);
    assert(encbound_cxx_guard_acquire(guard)==1);
    encbound_cxx_guard_abort(guard);
    assert(encbound_cxx_guard_acquire(guard)==1);
    encbound_cxx_guard_release(guard);
    assert(encbound_cxx_guard_acquire(guard)==0 && *(unsigned char *)raw==1);
    for(int rc=-1;rc<=0;++rc) {
        registration_result=rc;
        assert(encbound_cxx_atexit(callback,guard)==rc);
        assert(registered==callback && argument==guard && token==__dso_handle);
        registered(argument);
    }
    uintptr_t bad[]={raw,(uintptr_t)guard+12,
#ifdef ENCBOUND_MAC27
                    (uintptr_t)guard^(1ull<<32),
#endif
    };
    int expected[]={ENCBOUND_ERR_POLICY,ENCBOUND_ERR_RANGE,ENCBOUND_ERR_TAG};
    unsigned controls=0;
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) {
        for(unsigned operation=0;operation<3;++operation) {
            uint64_t before;memcpy(&before,(void*)raw,8);
            fake_abort_active=1;
            if(!setjmp(fake_abort_env)) {
                if(operation==0) encbound_cxx_guard_acquire((void*)bad[i]);
                else if(operation==1) encbound_cxx_guard_release((void*)bad[i]);
                else encbound_cxx_guard_abort((void*)bad[i]);
                assert(0);
            }
            fake_abort_active=0;
            assert(fake_abort_code==expected[i]);
            uint64_t after;memcpy(&after,(void*)raw,8);assert(after==before);
            ++controls;
        }
    }
    encbound_free(guard);
    printf("CXX LIFECYCLE NATIVE PASS: guard semantics, registration bits/results, %u attributed controls\n",controls);
}
