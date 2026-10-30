/* Test-only trusted responder. SDK session/key addresses never reach the app. */
#include <string.h>
#include "encbound_runtime.h"
#include "adapters.h"
static sgx_dh_session_t peer;
static sgx_key_128bit_t peer_key;
static uint32_t properties;
static void *span(const void *p,size_t n,int access)
{
#ifdef ENCBOUND_PROTECTED
    return (void *)encbound_require((uintptr_t)p,n,access);
#else
    (void)n;(void)access;return (void *)p;
#endif
}
#ifndef ENCBOUND_PROTECTED
#define encbound_yeez_peer_msg1 yeez_peer_msg1
#define encbound_yeez_peer_msg2 yeez_peer_msg2
#define encbound_yeez_peer_key yeez_peer_key
#endif
sgx_status_t encbound_yeez_peer_msg1(sgx_dh_msg1_t *out,uint32_t props)
{
    if(props>8)return SGX_ERROR_INVALID_PARAMETER;
    void *raw=span(out,sizeof(*out),ENCBOUND_ACCESS_WRITE);
    properties=props;
    sgx_dh_msg1_t local;
    sgx_status_t s=sgx_dh_init_session(SGX_DH_SESSION_RESPONDER,&peer);
    if(s==SGX_SUCCESS)s=sgx_dh_responder_gen_msg1(&local,&peer);
    if(s==SGX_SUCCESS)memcpy(raw,&local,sizeof local);
    return s;
}
sgx_status_t encbound_yeez_peer_msg2(const sgx_dh_msg2_t *input,sgx_dh_msg3_t *out,size_t capacity)
{
    size_t n=sizeof(*out)+properties;
    if(capacity<n)return SGX_ERROR_INVALID_PARAMETER;
    const void *a=span(input,sizeof(*input),ENCBOUND_ACCESS_READ);
    void *b=span(out,n,ENCBOUND_ACCESS_WRITE);
    sgx_dh_msg2_t m2;memcpy(&m2,a,sizeof m2);
    uint8_t storage[sizeof(*out)+8]={0};sgx_dh_msg3_t *m3=(void *)storage;
    m3->msg3_body.additional_prop_length=properties;
    memset(m3->msg3_body.additional_prop,0x63,properties);
    sgx_dh_session_enclave_identity_t identity;
    sgx_status_t s=sgx_dh_responder_proc_msg2(&m2,m3,&peer,&peer_key,&identity);
    if(s==SGX_SUCCESS)memcpy(b,m3,n);
    return s;
}
int encbound_yeez_peer_key(const sgx_key_128bit_t *key)
{return !memcmp(span(key,16,ENCBOUND_ACCESS_READ),peer_key,16);}
