/* Extend the real-checker/native-spy contract tests for the original keymgr. */
#define main prior_adapter_main
#include "adapters_test.c"
#undef main
#define span full_span
#define overlap full_overlap
#define malloc test_alloc
#include "full_adapters.c"
#undef malloc
#undef overlap
#undef span
static sgx_report_t sdk_report;
const sgx_report_t *sgx_self_report(void){++calls;return &sdk_report;}
sgx_status_t sgx_dh_responder_gen_msg1(sgx_dh_msg1_t *out,sgx_dh_session_t *session)
{
    ++calls;assert(session!=session_raw && session->sgx_dh_session[0]==0x20);
    assert(out!=msg1_raw);if(out)out->g_a.gx[0]=0x60;
    session->sgx_dh_session[0]=0x61;return service_status;
}
sgx_status_t sgx_dh_responder_proc_msg2(const sgx_dh_msg2_t *m2,sgx_dh_msg3_t *m3,
    sgx_dh_session_t *session,sgx_key_128bit_t *key,sgx_dh_session_enclave_identity_t *identity)
{
    ++calls;assert(session!=session_raw && session->sgx_dh_session[0]==0x20);
    assert(m2!=msg2_raw && key!=key_raw && identity!=identity_raw);
    if(m2)assert(m2->g_b.gx[0]==0x32);
    if(m3){assert(m3->msg3_body.additional_prop_length==expected_tail);
        if(expected_tail)m3->msg3_body.additional_prop[expected_tail-1]=0x70;}
    session->sgx_dh_session[0]=0x62;if(key)memset(key,0x63,16);if(identity)identity->isv_prod_id=0x64;
    return service_status;
}
int main(void)
{
    assert(prior_adapter_main()==0);
    unsigned original_denied=denied;
    void *rr,*mr;
    sgx_report_t *report=allocate(512,&rr);
    sgx_dh_session_t *session=allocate(256,&session_raw);
    sgx_dh_msg1_t *m1=allocate(1024,&msg1_raw);
    sgx_dh_msg2_t *m2=allocate(512,&msg2_raw);
    sgx_dh_msg3_t *m3=allocate(1024,&mr);
    sgx_key_128bit_t *key=allocate(16,&key_raw);
    sgx_dh_session_enclave_identity_t *identity=allocate(512,&identity_raw);
    memset(&sdk_report,0x55,sizeof sdk_report);
    DENY(encbound_yeez_report_copy((void *)((uintptr_t)report+100)),ENCBOUND_ERR_RANGE);
    assert(encbound_yeez_report_copy(report)==SGX_SUCCESS && ((uint8_t *)rr)[0]==0x55);
    state();service_status=SGX_SUCCESS;
    DENY(encbound_yeez_dh_gen1((void *)((uintptr_t)m1+512),session),ENCBOUND_ERR_RANGE);
    DENY(encbound_yeez_dh_gen1(m1,(void *)((uintptr_t)session+100)),ENCBOUND_ERR_RANGE);
    assert(encbound_yeez_dh_gen1(m1,session)==SGX_SUCCESS && ((uint8_t *)session_raw)[0]==0x61);
    state();service_status=SGX_ERROR_INVALID_STATE;
    assert(encbound_yeez_dh_gen1(m1,session)==service_status && ((uint8_t *)session_raw)[0]==0x61);
    state();((sgx_dh_msg2_t *)msg2_raw)->g_b.gx[0]=0x32;
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=8;expected_tail=8;
    DENY(encbound_yeez_dh_proc2((void *)((uintptr_t)m2+32),m3,session,key,identity),ENCBOUND_ERR_RANGE);
    DENY(encbound_yeez_dh_proc2(m2,(void *)((uintptr_t)m3+800),session,key,identity),ENCBOUND_ERR_RANGE);
    DENY(encbound_yeez_dh_proc2(m2,m3,(void *)((uintptr_t)session+100),key,identity),ENCBOUND_ERR_RANGE);
    DENY(encbound_yeez_dh_proc2(m2,m3,session,(void *)((uintptr_t)key+1),identity),ENCBOUND_ERR_RANGE);
    DENY(encbound_yeez_dh_proc2(m2,m3,session,key,(void *)((uintptr_t)identity+300)),ENCBOUND_ERR_RANGE);
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=800;
    DENY(encbound_yeez_dh_proc2(m2,m3,session,key,identity),ENCBOUND_ERR_RANGE);
    ((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop_length=8;
    unsigned before=calls;allocation_failure=1;
    assert(encbound_yeez_dh_proc2(m2,m3,session,key,identity)==SGX_ERROR_OUT_OF_MEMORY && calls==before);
    allocation_failure=0;
    assert(encbound_yeez_dh_proc2(m2,m3,session,key,identity)==service_status);
    assert(((uint8_t *)session_raw)[0]==0x62 && ((uint8_t *)key_raw)[0]==0x63);
    assert(((sgx_dh_session_enclave_identity_t *)identity_raw)->isv_prod_id==0x64);
    assert(((sgx_dh_msg3_t *)mr)->msg3_body.additional_prop[7]==0x70);
    void *trusted=(void *)(encbound_enclave_base()+0x300000);
    DENY(encbound_yeez_report_copy(trusted),ENCBOUND_ERR_POLICY);
    DENY(encbound_yeez_dh_gen1(trusted,session),ENCBOUND_ERR_POLICY);
    DENY(encbound_yeez_dh_proc2(trusted,m3,session,key,identity),ENCBOUND_ERR_POLICY);
    printf("YEEZ FULL ADAPTER NATIVE PASS extra_rejections=%u total=%u\n",denied-original_denied,denied);
    return 0;
}
