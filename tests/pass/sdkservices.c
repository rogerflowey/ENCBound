/*
 * ENCBound restart - step 5 pass input for inventory-driven redirection.
 *
 * Exercises the SDK sealing API, the generated-bridge OCALLs, and a cross-TU
 * application function. The pass must retarget the SDK/OCALL call sites to the
 * checked adapters named in the admitted inventory and leave the cross-TU
 * application function as an admitted call (not a raw SDK bypass). The types
 * here need only be sufficient for IR construction; the ABI is fixed by the
 * real SDK and EDL.
 */

#include <stddef.h>
#include <stdint.h>

typedef int sgx_status_t;
typedef struct {
    uint8_t bytes[80];
} sgx_sealed_data_t;

extern sgx_status_t sgx_seal_data(uint32_t, const uint8_t *, uint32_t,
                                  const uint8_t *, uint32_t,
                                  sgx_sealed_data_t *);
extern sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *, uint8_t *,
                                    uint32_t *, uint8_t *, uint32_t *);
extern sgx_status_t ocall_is_wallet(int *);
extern sgx_status_t ocall_save_wallet(int *, const uint8_t *, size_t);
extern sgx_status_t ocall_load_wallet(int *, uint8_t *, size_t);
extern sgx_status_t ocall_debug_print(const char *);
extern int seal_wallet(const void *, sgx_sealed_data_t *, size_t);

int sdkservices(int *retval, const char *str, uint8_t *buf, size_t n)
{
    sgx_sealed_data_t sealed;
    uint8_t plain[8];
    uint32_t plen = (uint32_t)sizeof(plain);
    int r = 0;

    (void)sgx_seal_data(0, NULL, 4, (const uint8_t *)str,
                        (uint32_t)sizeof(sealed) + 4u, &sealed);
    (void)sgx_unseal_data(&sealed, NULL, NULL, plain, &plen);
    (void)ocall_is_wallet(retval);
    (void)ocall_save_wallet(retval, buf, n);
    (void)ocall_load_wallet(retval, buf, n);
    (void)ocall_debug_print(str);
    r += seal_wallet(str, &sealed, n);
    return r + (int)plen;
}
