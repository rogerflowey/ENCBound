/* Differential oracle against the native system libm, including x87 values
 * that lose their fractional part if narrowed to double. */
#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
extern long double sgxfs_floorl(long double);
extern double sgxfs_floor(double);
extern double sgxfs_ceil(double);
int main(void) {
  const long double values[]={0.L,-0.L,0.25L,-0.25L,1.L,-1.L,1.75L,-1.75L,
    0x1.000000000000001p60L,-0x1.000000000000001p60L,LDBL_MIN,-LDBL_MIN,
    LDBL_MAX,-LDBL_MAX,INFINITY,-INFINITY,NAN};
  unsigned checks=0;
  for(unsigned i=0;i<sizeof values/sizeof values[0];++i) {
    long double x=values[i],a=sgxfs_floorl(x),b=floorl(x);
    assert((isnan(a)&&isnan(b)) || (a==b && !!signbit(a)==!!signbit(b)));++checks;
  }
  unsigned state=0x12345678;
  for(unsigned i=0;i<10000;++i) {
    state=state*1664525u+1013904223u;
    long double x=ldexpl((long double)(int)state/65536.L,(int)(state%150)-75);
    assert(sgxfs_floorl(x)==floorl(x));++checks;
    double d=(double)x;assert(sgxfs_floor(d)==floor(d));assert(sgxfs_ceil(d)==ceil(d));checks+=2;
  }
  printf("SGX-FS native selected math PASS: %u comparisons\n",checks);
}
