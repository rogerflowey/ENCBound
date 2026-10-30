/* Differential native test of compiler-private slot reuse. No SGX claim. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "encbound_runtime.h"
#include "encbound_internal.h"
#include "fake_platform.h"
static uint64_t state = 0x917bea672320aaffULL;
static uint64_t next(void) { state ^= state<<13; state ^= state>>7; state ^= state<<17; return state; }
static unsigned accepted, rejected;
static void compare(uintptr_t anchor, uintptr_t cap, size_t width, int kind) {
    uintptr_t expected = 0, token = encbound_span_prepare(anchor);
    int rc = encbound_check(cap, width, kind, &expected);
    fake_abort_active = 1;
    if (!setjmp(fake_abort_env)) {
        uintptr_t got = encbound_span_require(cap,width,kind,anchor,token);
        assert(rc == 0 && got == expected); ++accepted;
    } else { assert(rc != 0 && fake_abort_code == rc); ++rejected; }
    fake_abort_active = 0;
}
int main(void) {
    assert(encbound_runtime_init_with_key(1,2) == 0);
    uintptr_t heap = (uintptr_t)encbound_malloc(128);
    uintptr_t stack = encbound_stack_mint((void*)(encbound_base()+0x100000),128);
    assert(heap && stack && encbound_span_prepare(heap) && encbound_span_prepare(stack));
    uintptr_t anchors[] = {heap, heap+127, stack, stack+93, 0, UINT64_MAX,
        heap^(1ULL<<32), encbound_base()+0x200000, encbound_base()+0x300000};
    size_t widths[] = {0,1,8,16,127,128,129,SIZE_MAX,1ULL<<63};
    for (unsigned i=0;i<100000;i++) {
        uint64_t r=next(); uintptr_t anchor=anchors[i%9], cap;
        switch(i%8) {
        case 0: cap=anchor+(r&255); break;
        case 1: cap=heap^(1ULL<<(r%64)); break;
        case 2: cap=stack+(r&255); break;
        case 3: cap=r; break;
        case 4: cap=encbound_base()+(r&0x3ffffff); break;
        case 5: cap=(1ULL<<47)-(r&255); break;
        case 6: cap=heap-1; break;
        default: cap=anchor; break;
        }
        compare(anchor,cap,widths[(r>>9)%9],(r>>17)%5);
    }
    for(unsigned i=0;i<128;i++) for(unsigned w=1;w<=16;w++) {
        compare(heap,heap+i,w,1); compare(stack,stack+i,w,2);
    }
    assert(accepted && rejected);
    encbound_free((void*)heap);
    printf("SPAN RUNTIME PASS accepted=%u rejected=%u total=%u\n",accepted,rejected,accepted+rejected);
}
