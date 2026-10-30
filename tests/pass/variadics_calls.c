#include "variadics_fixture.h"
long API(test_variadics)(unsigned char *p, int mode) {
    if (mode) return API(va_bad)(mode,p,p);
    long bits = 0;
    if (API(va_mix)(0,1L,2L,3L,4L,5L,6L,7L,
                     1.,2.,3.,4.,5.,6.,7.,8.,9.,10.,p) == 94) bits |= 1;
    if (API(va_fp)(0.5,1.,2.,3.,4.,5.,6.,7.,8.,9.,10.) == 55.5) bits |= 2;
    if (API(va_many_fixed)(1L,2L,3L,4L,5L,6L,7L,
                           1.,2.,3.,4.,5.,6.,7.,8.,9.,10L,11.) == 94) bits |= 4;
    if (API(va_cursors)(0,1L,2L,3L) == 10) bits |= 8;
    if (API(va_promotions)(0,(signed char)-7,(short)12,(float)3.5) == 8) bits |= 16;
    if (API(va_recurse)(4,2L) == 14 && API(va_recurse)(0) == 0) bits |= 32;
    if (API(va_pointer)(0,p) == (uintptr_t)p) bits |= 64;
    for (int i=0;i<5;++i)
        if (API(va_recurse)(2,3L) != 7) return -1;
    return bits;
}
