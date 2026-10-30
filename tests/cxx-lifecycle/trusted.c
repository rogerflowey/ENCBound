/* Test-only diagnostics. Explicitly invoke the real SDK exit registry to test
 * callbacks in SIM; this is not a proposed application shutdown endpoint. */
#include <stdint.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
extern void do_atexit_aux(void);
extern void uninit_global_object(void);
extern int exercise(int);
extern unsigned long object_bits(void);
int test_finalize(void) { do_atexit_aux(); return exercise(1); }
int test_finish_arrays(void) {
    uninit_global_object();
    int result=exercise(3);
#ifdef ENCBOUND_PROTECTED
    // An exact arena-sized allocation proves all application allocations were
    // reclaimed and the buddy tree coalesced after the callbacks.
    void *whole=encbound_malloc(16u*1024*1024);
    if(!whole) return -5;
    encbound_free(whole);
#endif
    return result;
}
int isolation(void) {
#ifdef ENCBOUND_PROTECTED
    uintptr_t raw;
    if (encbound_check(object_bits(),1,ENCBOUND_ACCESS_READ,&raw)) return -1;
    if (encbound_check(raw,1,ENCBOUND_ACCESS_READ,&raw)!=ENCBOUND_ERR_POLICY) return -2;
    extern uintptr_t __encbound_gcaps_start[];
    if (encbound_check((uintptr_t)__encbound_gcaps_start,8,ENCBOUND_ACCESS_READ,&raw)!=ENCBOUND_ERR_POLICY) return -3;
    extern void *__dso_handle;
    if (encbound_check((uintptr_t)&__dso_handle,8,ENCBOUND_ACCESS_READ,&raw)!=ENCBOUND_ERR_POLICY) return -4;
#endif
    return 0;
}
