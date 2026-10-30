/* Ordinary application code shared by native and SDK SIM VLA tests. */
#include <stddef.h>
#include <stdint.h>
extern int vla_observe(const void *, size_t);
extern size_t vla_edge(const void *);

static size_t rounded(size_t n, size_t alignment) {
    size_t s=16;
    while (s<n || s<alignment) s*=2;
    return s;
}

/* Keep both source forms: O2 used to forward/reassociate these into an
 * unsigned product helper, rejecting valid negative signed factors. */
#define SIGNED_ARRAY_BODY(n) \
    volatile unsigned char a[n]; \
    if (!vla_observe((const void *)a,rounded(sizeof a,16))) return -40; \
    a[0]=1; a[sizeof a-1]=2; \
    return (int)(sizeof a+a[0]+a[sizeof a-1])
__attribute__((noinline)) int vla_signed_direct(long x,long y) {
    SIGNED_ARRAY_BODY(x*y);
}
__attribute__((noinline)) int vla_signed_stored(long x,long y) {
    long n=x*y;
    SIGNED_ARRAY_BODY(n);
}
__attribute__((noinline)) int vla_signed_nested(long x,long y,long z) {
    SIGNED_ARRAY_BODY(x*y*z);
}
__attribute__((noinline)) int vla_signed_scaled(long x,long y) {
    SIGNED_ARRAY_BODY((x*y)*4);
}
__attribute__((noinline)) int vla_signed_shifted(long x,long y) {
    SIGNED_ARRAY_BODY((x*4)*y);
}
__attribute__((noinline)) int vla_signed32(int x,int y) {
    SIGNED_ARRAY_BODY(x*y);
}
__attribute__((noinline)) int vla_unsigned(unsigned long x,unsigned long y) {
    SIGNED_ARRAY_BODY(x*y);
}
__attribute__((noinline)) int vla_unsigned32(unsigned x,unsigned y) {
    SIGNED_ARRAY_BODY(x*y);
}
#undef SIGNED_ARRAY_BODY

/* Scalar-only test entry shared by the native and SDK harnesses. */
int vla_signed_cases(long x,long y) {
    long n=x*y;
    if (vla_signed_direct(x,y)!=n+3 || vla_signed_stored(x,y)!=n+3 ||
        vla_signed_nested(x,-y,-2)!=2*n+3 ||
        vla_signed_scaled(x,y)!=4*n+3 || vla_signed_shifted(x,y)!=4*n+3 ||
        vla_signed32((int)x,(int)y)!=n+3 ||
        vla_unsigned((unsigned long)-x,(unsigned long)-y)!=n+3 ||
        vla_unsigned32((unsigned)-x,(unsigned)-y)!=n+3) return -41;
    return 0;
}
int vla_grid(size_t n,size_t m) {
    volatile unsigned char grid[n][m];
    if (!vla_observe((const void *)grid,rounded(n*m,16))) return -20;
    grid[0][0]=73;grid[n-1][m-1]=79;
    return grid[0][0]+grid[n-1][m-1]==152 ? 0 : -21;
}
__attribute__((noinline)) static int nested(size_t n, int early) {
    volatile unsigned char outer[n];
    if (!vla_observe((const void *)outer,rounded(n,16))) return -1;
    outer[0]=19; outer[n-1]=23;
    {
        unsigned char inner[n+3] __attribute__((aligned(256)));
        if (!vla_observe(inner,rounded(n+3,256))) return -2;
        inner[0]=37; inner[n+2]=41;
        if (early) return outer[0]+outer[n-1]+inner[0]+inner[n+2];
        if (inner[0]+inner[n+2]!=78) return -3;
    }
    return outer[0]+outer[n-1]+78;
}
__attribute__((noinline)) static int matrix(size_t n, size_t m) {
    volatile uint32_t grid[n][m];
    if (!vla_observe((const void *)grid,rounded(n*m*sizeof(uint32_t),16))) return -4;
    grid[0][0]=43; grid[n-1][m-1]=47;
    return grid[0][0]+grid[n-1][m-1]==90 && sizeof grid==n*m*sizeof(uint32_t);
}
__attribute__((noinline)) static int raw_alloca(size_t n) {
    unsigned char *a=__builtin_alloca(n);
    unsigned char *b=__builtin_alloca(n+1);
    if (!vla_observe(a,rounded(n,16)) || !vla_observe(b,rounded(n+1,16))) return 0;
    a[0]=11; b[n]=13;
    return a[0]+b[n]==24 && a!=b;
}
int vla_run(size_t n, int mode) {
    if (mode) {
        volatile uint32_t a[n];
        if (!vla_observe((const void *)a,mode<4 ? 16 : rounded(n*4,16))) return -5;
        if (mode==4) {
            /* A dynamic full-range check must reject before either byte writes. */
            size_t edge=vla_edge((const void *)a);
            typedef uint16_t unaligned16 __attribute__((aligned(1)));
            *(volatile unaligned16 *)((unsigned char *)a+edge)=0xabab;
        } else if (mode==5) {
            volatile uint32_t *p=(void *)((uintptr_t)a ^ (UINT64_C(1)<<32));
            *p=0x1234;
        }
        a[0]=71;
        return -6;
    }
    if (n<2 || n>257) return -7;
    if (nested(n,0)!=120 || nested(n,1)!=120 || !matrix(n,7) || !raw_alloca(n)) return -8;
    volatile unsigned char live[n];
    if (!vla_observe((const void *)live,rounded(n,16))) return -9;
    live[0]=59; live[n-1]=61;
    for (size_t i=0;i<160;++i) {
        size_t count=8193+(i&7);
        volatile unsigned char scratch[count];
        if (!vla_observe((const void *)scratch,rounded(count,16))) return -10;
        scratch[0]=(unsigned char)i; scratch[count-1]=(unsigned char)(i+1);
        if (scratch[0]!=(unsigned char)i || scratch[count-1]!=(unsigned char)(i+1)) return -11;
        if (i%3==0) continue;
        { volatile unsigned char inner[n+1];
          if (!vla_observe((const void *)inner,rounded(n+1,16))) return -12;
          inner[n]=67; if (inner[n]!=67) return -13; }
        if (i==159) break;
    }
    return live[0]+live[n-1]==120 ? 0 : -14;
}
