#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "encbound_runtime.h"
#include "encbound_internal.h"
#include "encbound_platform.h"
#include "fake_platform.h"
void *encbound_cxx_new(size_t);
void *encbound_cxx_new_nothrow(size_t,const void*);
void *encbound_cxx_new_aligned(size_t,size_t);
void *encbound_cxx_new_aligned_nothrow(size_t,size_t,const void*);
void encbound_cxx_delete(void*);
void encbound_cxx_delete_sized_aligned(void*,size_t,size_t);
int main(void) {
 assert(encbound_runtime_init_with_key(11,22)==0);
 assert(encbound_malloc(0)==0);
 assert(!encbound_alloc_aligned(12,0));
 assert(!encbound_alloc_aligned(12,3));
 assert(!encbound_alloc_aligned(12,(size_t)1<<25));
 for(size_t a=16;a<=(1<<24);a*=2) {
   void *p=encbound_cxx_new_aligned(3,a);
   uintptr_t raw=encbound_require((uintptr_t)p,3,ENCBOUND_ACCESS_WRITE);
   assert(!(raw&(a-1)));
   uintptr_t base;uint32_t radix;size_t requested;
   assert(encbound_cap_to_heap_slot((uintptr_t)p,&base,&radix)==0);
   assert(((size_t)1<<radix)==a);
   assert(encbound_heap_requested(base,radix,&requested)==0 && requested==3);
   assert(encbound_free_checked((char*)p+1)==ENCBOUND_ERR_RANGE);
   encbound_cxx_delete_sized_aligned(p,3,a);
 }
 void *zero=encbound_cxx_new(0);assert(zero);encbound_cxx_delete(zero);
 void *p=encbound_cxx_new_aligned(1,1<<24);
 assert(!encbound_cxx_new_nothrow(1,0));
 assert(!encbound_cxx_new_aligned_nothrow((size_t)-1,64,0));
 fake_abort_active=1;
 if (!setjmp(fake_abort_env)) { encbound_cxx_new(1); assert(0); }
 assert(fake_abort_code==ENCBOUND_ERR_DEPLETED);fake_abort_active=0;
 encbound_cxx_delete(p);
 p=encbound_cxx_new(1<<24);encbound_cxx_delete(p);
 puts("ALIGNED/CXX ALLOCATION PASS (native real runtime)");
}
