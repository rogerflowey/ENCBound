#include <stdarg.h>
#include <stdint.h>
#ifdef ORACLE
#define API_(n) native_##n
#define API(n) API_(n)
#else
#define API(n) n
#endif
long API(va_mix)(int, ...);
double API(va_fp)(double, ...);
long API(va_many_fixed)(long,long,long,long,long,long,long,
                       double,double,double,double,double,double,double,double,double,...);
long API(va_cursors)(int, ...);
long API(va_promotions)(int, ...);
long API(va_recurse)(int, ...);
uintptr_t API(va_pointer)(int, ...);
long API(va_forward)(int, va_list);
long API(va_bad)(int, unsigned char *, ...);
long API(test_variadics)(unsigned char *, int);
