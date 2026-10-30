/* Optional trusted full AES-128-CMAC for the fixed six-byte message.
 * Independently written in this repository from FIPS 197 / SP 800-38B;
 * adapted from experiments/mac-microbench/mac.h (2026-10-13). No external code
 * copied. GNU vector builtins avoid pulling host headers into the SDK enclave.
 * Only compile with AES-NI enabled, after the experiment's CPU preflight. */
#ifndef ENCBOUND_AES_CMAC_H
#define ENCBOUND_AES_CMAC_H
#include <stdint.h>
#include <string.h>
typedef long long encbound_v128 __attribute__((vector_size(16)));
typedef int encbound_v4i __attribute__((vector_size(16)));
typedef struct { encbound_v128 round[11],first6; } encbound_cmac_context;
#define CMAC_INLINE static inline __attribute__((always_inline))
CMAC_INLINE encbound_v128 cmac_shift4(encbound_v128 x) {
    __asm__("pslldq $4, %0" : "+x"(x));return x;
}
CMAC_INLINE encbound_v128 cmac_expand(encbound_v128 k,encbound_v128 a) {
    encbound_v4i w=(encbound_v4i)a;
    a=(encbound_v128)__builtin_shufflevector(w,w,3,3,3,3);
    encbound_v128 t=cmac_shift4(k);k^=t;t=cmac_shift4(t);k^=t;t=cmac_shift4(t);
    return k^t^a;
}
CMAC_INLINE encbound_v128 cmac_finish(const encbound_cmac_context *c,encbound_v128 x) {
#define ROUND(N) x=__builtin_ia32_aesenc128(x,c->round[N])
    ROUND(1);ROUND(2);ROUND(3);ROUND(4);ROUND(5);ROUND(6);ROUND(7);ROUND(8);ROUND(9);
#undef ROUND
    return __builtin_ia32_aesenclast128(x,c->round[10]);
}
CMAC_INLINE void cmac_double(uint8_t b[16]) {
    unsigned carry=b[0]>>7;
    for(unsigned i=0;i<15;i++)b[i]=(uint8_t)((b[i]<<1)|(b[i+1]>>7));
    b[15]=(uint8_t)((b[15]<<1)^(0x87u*carry));
}
static void encbound_cmac_init(encbound_cmac_context *c,uint64_t k0,uint64_t k1) {
    c->round[0]=(encbound_v128){(long long)k0,(long long)k1};
#define EXPAND(N,R) c->round[N]=cmac_expand(c->round[N-1],__builtin_ia32_aeskeygenassist128(c->round[N-1],R))
    EXPAND(1,1);EXPAND(2,2);EXPAND(3,4);EXPAND(4,8);EXPAND(5,16);
    EXPAND(6,32);EXPAND(7,64);EXPAND(8,128);EXPAND(9,27);EXPAND(10,54);
#undef EXPAND
    encbound_v128 v=cmac_finish(c,c->round[0]);uint8_t b[16];memcpy(b,&v,16);
    cmac_double(b);cmac_double(b);b[6]^=0x80;memcpy(&v,b,16);
    c->first6=v^c->round[0];
}
CMAC_INLINE encbound_v128 encbound_cmac_full6(const encbound_cmac_context *c,uint8_t domain,uint8_t radix,uint32_t offset) {
    uint64_t p=(uint64_t)domain|((uint64_t)radix<<8)|((uint64_t)offset<<16);
    return cmac_finish(c,((encbound_v128){(long long)p,0})^c->first6);
}
CMAC_INLINE uint64_t encbound_cmac27(const encbound_cmac_context *c,uint8_t domain,uint8_t radix,uint32_t offset) {
    encbound_v128 v=encbound_cmac_full6(c,domain,radix,offset);
    return __builtin_bswap32((uint32_t)v[0])>>5;
}
#undef CMAC_INLINE
#endif
