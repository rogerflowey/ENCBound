#include "fixture.h"

static long alternate(int unused, ...)
{
    va_list ap; va_start(ap, unused); long n=va_arg(ap, long); va_end(ap);
    return n+100;
}
static long invoke(generic_function fn, long value)
{ return ((long (*)(int, ...))fn)(0, value); }

long API(indirect_case)(unsigned char *p, int mode)
{
    if (mode) return ((long (*)(int, unsigned char *, ...))API(callback_get)(7))(mode, p, p);
    /* Each bit has an independent numeric/pointer oracle in the host harness. */
    long bits=0;
    if (((long (*)(int, ...))API(callback_get)(0))(0,1L,2L,3L,4L,5L,6L,7L,
            1.,2.,3.,4.,5.,6.,7.,8.,9.,10.,p)==94) bits|=1;
    if (((double (*)(double, ...))API(callback_get)(1))(.5,1.,2.,3.,4.,5.,6.,7.,8.,9.,10.)==55.5) bits|=2;
    if (((long (*)(long,long,long,long,long,long,long,double,double,double,double,double,double,double,double,double,...))
            API(callback_get)(2))(1L,2L,3L,4L,5L,6L,7L,1.,2.,3.,4.,5.,6.,7.,8.,9.,10L,11.)==94) bits|=4;
    if (((long (*)(int, ...))API(callback_get)(3))(0,1L,2L,3L)==10) bits|=8;
    if (((long (*)(int, ...))API(callback_get)(4))(0,(signed char)-7,(short)12,(float)3.5)==8) bits|=16;
    if (((long (*)(int, ...))API(callback_get)(5))(4,2L)==14 &&
        ((long (*)(int, ...))API(callback_get)(5))(0)==0) bits|=32;
    if (((uintptr_t (*)(int, ...))API(callback_get)(6))(0,p)==(uintptr_t)p) bits|=64;
    generic_function before=API(callback_replace)(5, (generic_function)alternate);
    int replaced=invoke(API(callback_get)(5), 7)==107;
    generic_function replaced_fn=API(callback_replace)(5, 0);
    if (replaced && replaced_fn==(generic_function)alternate && before==API(callback_get)(5) &&
        ((long (*)(int, ...))API(callback_get)(5))(2,3L)==7) bits|=128;
    int cell=29;
    int (*control)(int,int,...)=(int (*)(int,int,...))API(callback_get)(8);
    if (control(11,0)==11 && control(11,1,-7)==4 && control(11,2,&cell)==40 && cell==43) bits|=256;
    void *(*remap)(void *,unsigned long,unsigned long,int,...)=
        (void *(*)(void *,unsigned long,unsigned long,int,...))API(callback_get)(9);
    void *(*identity)(void *,int,...)=(void *(*)(void *,int,...))API(callback_get)(10);
    if (remap(p,5,7,0)==p && remap(0,5,7,1,p)==p && identity(p,19,&cell)==p && cell==19) bits|=512;
    return bits;
}

