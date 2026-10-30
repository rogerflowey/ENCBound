/* Original analyzer/key-manager closure only. Never include in trusted code. */
#pragma once
#include "services.h"
#include <sgx_utils.h>
#include <sgx_tseal.h>
#ifdef __cplusplus
extern "C" {
#endif
const sgx_report_t *yeez_self_report(void);
sgx_status_t yeez_report_copy(sgx_report_t *);
sgx_status_t yeez_dh_gen1(sgx_dh_msg1_t *,sgx_dh_session_t *);
sgx_status_t yeez_dh_proc2(const sgx_dh_msg2_t *,sgx_dh_msg3_t *,sgx_dh_session_t *,sgx_key_128bit_t *,sgx_dh_session_enclave_identity_t *);
sgx_status_t kms_seal(uint32_t,const uint8_t *,uint32_t,const uint8_t *,uint32_t,sgx_sealed_data_t *);
sgx_status_t kms_unseal(const sgx_sealed_data_t *,uint8_t *,uint32_t *,uint8_t *,uint32_t *);
uint32_t kms_sealed_size(uint32_t,uint32_t);
uint32_t kms_text_len(const sgx_sealed_data_t *);
uint32_t kms_aad_len(const sgx_sealed_data_t *);
sgx_status_t kms_create_report(const sgx_target_info_t *,const sgx_report_data_t *,sgx_report_t *);
#ifdef __cplusplus
}
#endif
#define sgx_self_report yeez_self_report
#define sgx_dh_responder_gen_msg1 yeez_dh_gen1
#define sgx_dh_responder_proc_msg2 yeez_dh_proc2
#define sgx_seal_data kms_seal
#define sgx_unseal_data kms_unseal
#define sgx_calc_sealed_data_size kms_sealed_size
#define sgx_get_encrypt_txt_len kms_text_len
#define sgx_get_add_mac_txt_len kms_aad_len
#define sgx_create_report kms_create_report
#define vsnprintf app_fmt_vsnprintf
