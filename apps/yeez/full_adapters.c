/* Additional exact trusted services for the original key-manager closure. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sgx_dh.h>
#include <sgx_utils.h>
#include "encbound_runtime.h"
extern int memset_s(void *,size_t,int,size_t);
#ifndef ENCBOUND_PROTECTED
#define encbound_yeez_report_copy yeez_report_copy
#define encbound_yeez_dh_gen1 yeez_dh_gen1
#define encbound_yeez_dh_proc2 yeez_dh_proc2
#endif
static void *span(const void *p,size_t n,int access)
{
#ifdef ENCBOUND_PROTECTED
    return (void *)encbound_require((uintptr_t)p,n,access);
#else
    (void)n;(void)access;return (void *)p;
#endif
}
static int overlap(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return a && b && an && bn && (x<=y ? y-x<an : x-y<bn);
}
sgx_status_t encbound_yeez_report_copy(sgx_report_t *out)
{
    if(!out)return SGX_ERROR_INVALID_PARAMETER;
    void *d=span(out,sizeof(*out),ENCBOUND_ACCESS_WRITE);
    const sgx_report_t *report=sgx_self_report();
    if(!report)return SGX_ERROR_UNEXPECTED;
    memcpy(d,report,sizeof(*out));return SGX_SUCCESS;
}
sgx_status_t encbound_yeez_dh_gen1(sgx_dh_msg1_t *m1,sgx_dh_session_t *session)
{
    if(!session)return SGX_ERROR_INVALID_PARAMETER;
    void *s=span(session,sizeof(*session),ENCBOUND_ACCESS_READWRITE);
    void *m=m1 ? span(m1,sizeof(*m1),ENCBOUND_ACCESS_READWRITE) : NULL;
    if(overlap(s,sizeof(*session),m,sizeof(*m1)))return SGX_ERROR_INVALID_PARAMETER;
    sgx_dh_session_t ls;sgx_dh_msg1_t lm;
    memcpy(&ls,s,sizeof ls);if(m)memcpy(&lm,m,sizeof lm);
    sgx_status_t r=sgx_dh_responder_gen_msg1(m ? &lm : NULL,&ls);
    memcpy(s,&ls,sizeof ls);if(m)memcpy(m,&lm,sizeof lm);
    memset_s(&ls,sizeof ls,0,sizeof ls);return r;
}
sgx_status_t encbound_yeez_dh_proc2(const sgx_dh_msg2_t *m2,sgx_dh_msg3_t *m3,sgx_dh_session_t *session,
    sgx_key_128bit_t *key,sgx_dh_session_enclave_identity_t *identity)
{
    if(!session)return SGX_ERROR_INVALID_PARAMETER;
    void *s=span(session,sizeof(*session),ENCBOUND_ACCESS_READWRITE);
    const void *a=m2 ? span(m2,sizeof(*m2),ENCBOUND_ACCESS_READ) : NULL;
    void *k=key ? span(key,sizeof(*key),ENCBOUND_ACCESS_READWRITE) : NULL;
    void *i=identity ? span(identity,sizeof(*identity),ENCBOUND_ACCESS_READWRITE) : NULL;
    void *b=NULL;size_t total=0;sgx_dh_msg3_t header={0};
    if(m3){
        memcpy(&header,span(m3,sizeof header,ENCBOUND_ACCESS_READWRITE),sizeof header);
        if(header.msg3_body.additional_prop_length>UINT_MAX-sizeof header)return SGX_ERROR_INVALID_PARAMETER;
        total=sizeof header+header.msg3_body.additional_prop_length;
        b=span(m3,total,ENCBOUND_ACCESS_READWRITE);
    }
    const void *ptrs[]={s,a,b,k,i};
    const size_t sizes[]={sizeof(*session),sizeof(*m2),total,sizeof(*key),sizeof(*identity)};
    for(unsigned x=0;x<5;++x)for(unsigned y=x+1;y<5;++y)
        if(overlap(ptrs[x],sizes[x],ptrs[y],sizes[y]))return SGX_ERROR_INVALID_PARAMETER;
    sgx_dh_msg3_t *lb=NULL;
    if(b){lb=malloc(total);if(!lb)return SGX_ERROR_OUT_OF_MEMORY;
        memcpy(lb,b,total);lb->msg3_body.additional_prop_length=header.msg3_body.additional_prop_length;}
    sgx_dh_session_t ls;sgx_dh_msg2_t la;sgx_key_128bit_t lk={0};sgx_dh_session_enclave_identity_t li={0};
    memcpy(&ls,s,sizeof ls);if(a)memcpy(&la,a,sizeof la);if(k)memcpy(&lk,k,sizeof lk);if(i)memcpy(&li,i,sizeof li);
    sgx_status_t r=sgx_dh_responder_proc_msg2(a ? &la : NULL,lb,&ls,k ? &lk : NULL,i ? &li : NULL);
    memcpy(s,&ls,sizeof ls);if(b)memcpy(b,lb,total);if(k)memcpy(k,&lk,sizeof lk);if(i)memcpy(i,&li,sizeof li);
    memset_s(&ls,sizeof ls,0,sizeof ls);memset_s(&lk,sizeof lk,0,sizeof lk);
    if(lb){memset_s(lb,total,0,total);free(lb);}return r;
}
