/* Application-only redirects; trusted SDK/adapter/bridge builds omit this file. */
#pragma once
#include <string.h>
#include <sgx_trts.h>
#include "adapters.h"
#define sgx_read_rand yeez_read_rand
#define sgx_rijndael128GCM_encrypt yeez_encrypt
#define sgx_rijndael128GCM_decrypt yeez_decrypt
#define sgx_rijndael128_cmac_msg yeez_cmac
#define sgx_sha256_msg yeez_sha256
#define sgx_dh_init_session yeez_dh_init
#define sgx_LAv1_initiator_proc_msg1 yeez_dh_msg1
#define sgx_LAv1_initiator_proc_msg3 yeez_dh_msg3
#define memset_s yeez_memset_s
