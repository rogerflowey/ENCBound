/* Application-only names. SDK/bridge compilation must not include this file. */
#define sgx_ra_init kms_ra_init
#define sgx_ra_get_keys kms_ra_get_keys
#define sgx_ra_close kms_ra_close
#define sgx_create_report kms_create_report
#define sgx_read_rand kms_read_rand
#define sgx_rijndael128GCM_encrypt kms_encrypt
#define sgx_rijndael128GCM_decrypt kms_decrypt
#define sgx_rijndael128_cmac_msg kms_cmac
#define sgx_seal_data kms_seal
#define sgx_unseal_data kms_unseal
#define sgx_calc_sealed_data_size kms_sealed_size
#define sgx_get_encrypt_txt_len kms_text_len
#define sgx_get_add_mac_txt_len kms_aad_len
#define memset_s kms_memset_s
#define consttime_memequal kms_memequal
#define vsnprintf app_fmt_vsnprintf
