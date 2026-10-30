/* Test-only scalar entry; bridge initialization/serialization remains ordinary. */
#include <stddef.h>
extern int vla_run(size_t,int);
extern int vla_grid(size_t,size_t);
extern int vla_cpp(size_t);
extern int vla_signed_cases(long,long),vla_cpp_signed(long,long);
static unsigned destroyed;
void vla_destroyed(int value) { destroyed+=value==7 ? 1 : 1000000; }
int run_test(size_t n,int mode) {
    if (mode==6) return vla_grid(n,3);
    int result=vla_run(n,mode);
    if (mode || result) return result;
    if (vla_signed_cases(-2,-3) || vla_signed_cases(-17,-19)) return -31;
    destroyed=0;
    if (vla_cpp_signed(-2,-3)!=42 || destroyed!=6) return -32;
    destroyed=0;
    return vla_cpp(n)==(int)(7*n) && destroyed==n ? 0 : -30;
}
