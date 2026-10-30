#include "variadics_fixture.h"

long API(va_mix)(int unused, ...) {
    va_list ap;
    va_start(ap, unused);
    long total = 0;
    for (int i = 0; i < 7; ++i) total += va_arg(ap, long);
    for (int i = 0; i < 10; ++i) total += (long)va_arg(ap, double);
    unsigned char *p = va_arg(ap, unsigned char *);
    total += *p;
    ++*p;
    va_end(ap);
    return total;
}
double API(va_fp)(double named, ...) {
    va_list ap;
    va_start(ap, named);
    double total = named;
    for (int i = 0; i < 10; ++i) total += va_arg(ap, double);
    va_end(ap);
    return total;
}
long API(va_many_fixed)(long a,long b,long c,long d,long e,long f,long g,
                       double h,double i,double j,double k,double l,double m,
                       double n,double o,double last,...) {
    va_list ap;
    va_start(ap,last);
    long result = va_arg(ap,long) + (long)va_arg(ap,double);
    va_end(ap);
    return result+a+b+c+d+e+f+g+(long)(h+i+j+k+l+m+n+o+last);
}
__attribute__((noinline)) long API(va_forward)(int n, va_list ap) {
    long sum = 0;
    for (int i = 0; i < n; ++i) sum += va_arg(ap,long);
    return sum;
}
long API(va_cursors)(int unused, ...) {
    va_list ap, cp, again;
    va_start(ap,unused);
    va_copy(cp,ap);
    long a = va_arg(ap,long), b = va_arg(cp,long), c = va_arg(cp,long);
    va_start(again,unused);
    long d = va_arg(again,long);
    long e = API(va_forward)(2,ap);
    va_end(again); va_end(cp); va_end(ap);
    return a+b+c+d+e;
}
long API(va_promotions)(int unused, ...) {
    va_list ap;
    va_start(ap,unused);
    int a = va_arg(ap,int), b = va_arg(ap,int);
    double c = va_arg(ap,double);
    va_end(ap);
    return a+b+(long)c;
}
long API(va_recurse)(int depth, ...) {
    va_list ap;
    va_start(ap,depth);
    long value = depth ? va_arg(ap,long) : 0;
    va_end(ap);
    return depth ? value + API(va_recurse)(depth-1,value+1) : 0;
}
uintptr_t API(va_pointer)(int unused, ...) {
    va_list ap;
    va_start(ap,unused);
    void *p = va_arg(ap,void *);
    va_end(ap);
    return (uintptr_t)p;
}
struct TestVa { unsigned gp, fp; void *overflow, *regs; };
long API(va_bad)(int mode, unsigned char *p, ...) {
    va_list ap;
    va_start(ap,p);
    struct TestVa *fields = (void *)ap;
    if (mode == 1) { unsigned char *q = va_arg(ap,unsigned char *); *q=99; }
    if (mode == 2) fields->regs = p;
    if (mode == 3) { fields->gp=48; fields->overflow=p; }
    if (mode == 4) {
        fields->gp=40;
        fields->regs=(void *)((uintptr_t)fields->regs+212);
    } /* register path: 8-byte access at offset 252 of the 256-byte slot */
    if (mode == 5) fields->regs=(void *)((uintptr_t)fields->regs ^ (UINT64_C(1)<<32));
    long result = mode == 1 ? 0 : va_arg(ap,long);
    va_end(ap);
    return result;
}
