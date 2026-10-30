/* Bounded driver for original user_check APIs. Oracles use host double math,
 * never another enclave implementation. All SDK statuses and array elements
 * are checked. Random shares are intentionally not compared byte for byte. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

#define MAX_N 64
#define SHARES 5
static unsigned calls, comparisons;
static double max_error;
static void check_status(sgx_status_t s, int line) {
    ++calls;
    if (s) { fprintf(stderr,"ECALL line %d: status=%#x\n",line,s); exit(10); }
}
#define CALL(expr) check_status((expr),__LINE__)

static void compare(const char *op, int test, int n, const float *got, const double *want) {
    for (int i=0;i<n;++i) {
        double err=fabs((double)got[i]-want[i]);
        if (!isfinite(got[i]) || !isfinite(want[i]) || err>0.000006+0.00003*fabs(want[i])) {
            fprintf(stderr,"ORACLE %s case=%d index=%d got=%.9g expected=%.17g error=%.9g\n",
                    op,test,i,got[i],want[i],err); exit(11);
        }
        if (err>max_error) max_error=err;
        ++comparisons;
    }
}

static void guard(float *a, int n) { for(int i=0;i<SHARES*n+2;++i) a[i]=1234567.0f; }
static void guards(const float *a, int n) {
    if(a[0]!=1234567.0f || a[SHARES*n+1]!=1234567.0f) { fputs("output guard changed\n",stderr);exit(12); }
}

static void reference(int op, int n, int m, int c, const float *x, const float *g,
                      double *y, double *dy) {
    if(op<2) {
        for(int j=0;j<n;++j) {
            if(op==0) { y[j]=x[j]>=1e-7f?x[j]:0; dy[j]=x[j]>=1e-7f?g[j]:0; }
            else { y[j]=1/(1+exp(-(double)x[j]));dy[j]=g[j]*y[j]*(1-y[j]); }
        }
    } else {
        for(int row=0;row<m;++row) {
            double largest=x[row*c],sum=0,dot=0;
            for(int j=1;j<c;++j) if(x[row*c+j]>largest) largest=x[row*c+j];
            for(int j=0;j<c;++j) sum+=exp((double)x[row*c+j]-largest);
            for(int j=0;j<c;++j) { y[row*c+j]=exp((double)x[row*c+j]-largest)/sum;dot+=g[row*c+j]*y[row*c+j]; }
            for(int j=0;j<c;++j) dy[row*c+j]=y[row*c+j]*(g[row*c+j]-dot);
        }
    }
}

int main(int argc,char **argv) {
    if(argc!=2)return 2;
    sgx_enclave_id_t eid=0;
    sgx_status_t s=sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL);
    if(s) { fprintf(stderr,"create=%#x\n",s);return 3; }
    four_app_permissions(argv[1]);
    for(int round=0;round<3;++round) for(int test=0;test<8;++test) {
        int c=test==6?1:4,m=test==6?1:test==7?8:3,n=m*c;
        float x[MAX_N],g[MAX_N],decoded[MAX_N],dg[MAX_N];
        float ex[SHARES*MAX_N+2],eg[SHARES*MAX_N+2],out[SHARES*MAX_N+2];
        double expected[MAX_N],y[MAX_N],dy[MAX_N];
        for(int j=0;j<n;++j) {
            x[j]=test==0?0:test==1?1:test==2?(j%2?3:-3):
                test==3?(float)((j*7)%13-6)*0.25f:
                test==4?(j%4==0?-80:j%4==1?80:j%4==2?-20:20):
                test==5?(j%4==0?-2e-7f:j%4==1?0:j%4==2?0.5e-7f:2e-7f):
                test==6?0.5f:(float)((j*11)%19-9)*0.125f;
            g[j]=(float)((j*5+round*3)%11-5)*0.125f;
            expected[j]=x[j];
        }
        guard(ex,n);guard(eg,n);
        CALL(ecall_encrypt(eid,x,n,ex+1));guards(ex,n);
        CALL(ecall_decrypt(eid,ex+1,n,decoded));compare("encode/decode",test,n,decoded,expected);
        CALL(ecall_encrypt(eid,g,n,eg+1));guards(eg,n);
        for(int j=0;j<n;++j)expected[j]=g[j];
        CALL(ecall_decrypt(eid,eg+1,n,dg));compare("gradient encode/decode",test,n,dg,expected);
        /* Exact share fixture preserves the ReLU threshold at tiny magnitudes;
         * the separate round trip above still checks original encryption. */
        if(test==5) {
            memset(ex+1,0,SHARES*n*sizeof(float));memset(eg+1,0,SHARES*n*sizeof(float));
            for(int j=0;j<n;++j) { ex[1+4*n+j]=decoded[j]=x[j];eg[1+4*n+j]=dg[j]=g[j]; }
        }
        float ex_before[SHARES*MAX_N],eg_before[SHARES*MAX_N];
        memcpy(ex_before,ex+1,SHARES*n*sizeof(float));memcpy(eg_before,eg+1,SHARES*n*sizeof(float));
        for(int op=0;op<3;++op) {
            reference(op,n,m,c,decoded,dg,y,dy);
            guard(out,n);
            if(op==0) CALL(ecall_relu(eid,ex+1,n,out+1));
            else if(op==1) CALL(ecall_sigmoid(eid,ex+1,n,out+1));
            else CALL(ecall_softmax(eid,ex+1,n,m,c,out+1));
            guards(out,n);
            float actual[MAX_N];CALL(ecall_decrypt(eid,out+1,n,actual));compare(op==0?"relu":op==1?"sigmoid":"softmax",test,n,actual,y);
            guard(out,n);
            if(op==0) CALL(ecall_relu_grad(eid,ex+1,eg+1,n,out+1));
            else if(op==1) CALL(ecall_sigmoid_grad(eid,ex+1,eg+1,n,out+1));
            else CALL(ecall_softmax_grad(eid,ex+1,eg+1,n,m,c,out+1));
            guards(out,n);
            CALL(ecall_decrypt(eid,out+1,n,actual));compare(op==0?"relu_grad":op==1?"sigmoid_grad":"softmax_grad",test,n,actual,dy);
        }
        if(memcmp(ex_before,ex+1,SHARES*n*sizeof(float)) || memcmp(eg_before,eg+1,SHARES*n*sizeof(float)))return 13;
    }
    if(sgx_destroy_enclave(eid)!=SGX_SUCCESS)return 4;
    printf("{\"result\":\"PASS\",\"calls\":%u,\"comparisons\":%u,\"max_absolute_error\":%.17g,\"rounds\":3,\"fixtures\":8}\n",calls,comparisons,max_error);
    return 0;
}
