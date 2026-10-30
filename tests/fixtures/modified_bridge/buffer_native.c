/* Exercise actual native-AST-emitted OCALLs, including exact extents and
 * read/write direction. Rejection children terminate immediately. */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
int bridge_copy_fail;
#include "sample_t.c"
static void *transport;
int run(Inner small,Packet *v,char *text,uint32_t *words,size_t n,bool *ok,double number) {
    (void)small;(void)v;(void)text;(void)words;(void)n;(void)ok;(void)number;return 0;
}
int sgx_is_outside_enclave(const void *p,size_t n) { (void)n;return p!=NULL; }
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
    (void)index;ms_emit_t *m=data;
    assert(!memcmp(m->ms_prefix,"seed123",8));
    /* Intel's OCALL multiplication wraps in size_t. Zero-byte marshaling must
     * not cause a raw read, while the nonzero case copies exactly one element. */
    if(m->ms_n==1)assert(m->ms_words[0]==23);
    else assert(m->ms_n==SIZE_MAX/4+1);
    m->ms_prefix[0]='!';m->ms_retval=17;return SGX_SUCCESS;
}
int main(void) {
#ifdef ENCBOUND_PROTECTED
    assert(encbound_runtime_init_with_key(1,2)==0);
    char *p=encbound_malloc(16),*w=encbound_malloc(16);
    char *raw=(void*)encbound_require((uintptr_t)p,16,3);
    uint32_t *words=(void*)encbound_require((uintptr_t)w,16,3);
#else
    char *p=malloc(16),*w=malloc(16),*raw=p;uint32_t *words=(void*)w;
#endif
    memcpy(raw,"seed123",8);words[0]=23;
    assert(emit((int*)(p+8),p,(uint32_t*)w,1)==SGX_SUCCESS);
    int result;memcpy(&result,raw+8,4);assert(result==17 && raw[0]=='!');
    memcpy(raw,"seed123",8);
    assert(emit((int*)(p+8),p,(uint32_t*)w,SIZE_MAX/4+1)==SGX_SUCCESS);
#ifdef ENCBOUND_PROTECTED
    for(unsigned mode=0;mode<3;++mode) {
        pid_t child=fork();assert(child>=0);
        if(!child) {
            unsigned char snapshot[16];memcpy(snapshot,raw,16);
            fake_abort_active=1;
            if(!setjmp(fake_abort_env)) {
                emit((int*)(p+(mode==0?15:8)),mode==1?p+12:p,
                     (uint32_t*)(mode==2?w+12:w),mode==2?2:1);
                _exit(90);
            }
            assert(fake_abort_code==ENCBOUND_ERR_RANGE && !transport);
            assert(!memcmp(snapshot,raw,16));_exit(0);
        }
        int status;assert(waitpid(child,&status,0)==child);
        assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
    }
    encbound_free(p);encbound_free(w);
#else
    free(p);free(w);
#endif
    return 0;
}
