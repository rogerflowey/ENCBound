/* Layout check for the pinned SDK 2.26 private RA database item.
 *
 * tkey_exchange.cpp keeps `ra_db_item_t` in a private packed structure.  The
 * C16 control uses sk_key's offset to construct a hostile `sp_db_item_t`
 * pointer; a changed SDK pin must fail this check instead of silently reading
 * the wrong field.  SDK SIM / host diagnostics only.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sgx_key_exchange.h>
#include <sgx_quote.h>

typedef enum { ra_inited = 0, ra_get_gaed, ra_proc_msg2ed } ra_state;

typedef struct _ra_db_item_t {
    sgx_ec256_public_t       g_a;
    sgx_ec256_public_t       g_b;
    sgx_ec_key_128bit_t      vk_key;
    sgx_ec256_public_t       sp_pubkey;
    sgx_ec256_private_t      a;
    sgx_ps_sec_prop_desc_t   ps_sec_prop;
    sgx_ec_key_128bit_t      mk_key;
    sgx_ec_key_128bit_t      sk_key;
    sgx_ec_key_128bit_t      smk_key;
    sgx_quote_nonce_t        quote_nonce;
    sgx_target_info_t        qe_target;
    ra_state                 state;
    uint32_t                 item_lock;
    uintptr_t                derive_key_cb;
} __attribute__((packed)) ra_db_item_t;

int main(void)
{
    printf("%zu %zu %zu %zu\n", sizeof(ra_db_item_t),
           offsetof(ra_db_item_t, mk_key), offsetof(ra_db_item_t, sk_key),
           offsetof(ra_db_item_t, smk_key));
    return 0;
}
