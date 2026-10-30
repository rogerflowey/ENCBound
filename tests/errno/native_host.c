/* Execute the actual generated untrusted bridge in the native transport.
 * Rename public functions only to coexist with enclave functions in one ELF. */
#define errno_case host_ecall_errno_case
#define errno_read host_ecall_errno_read
#define errno_write host_ecall_errno_write
#define errno_pointer host_ecall_errno_pointer
#define errno_access host_ecall_errno_access
#define errno_sdk_address host_ecall_errno_sdk_address
#define errno_sdk_read host_ecall_errno_sdk_read
#define errno_exchange host_ocall_errno_exchange
#define errno_void host_ocall_errno_void
#define errno_naked host_ocall_errno_naked
#define errno_plain host_ocall_errno_plain
#include "probe_u.c"
#include "host_services.c"

sgx_status_t sgx_ecall(sgx_enclave_id_t eid, const int index,
                       const void *table, void *data)
{
    (void)eid; (void)index; (void)table; (void)data;
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t errno_host_dispatch(unsigned index, void *data)
{
    assert(index < ocall_table_probe.nr_ocall);
    sgx_status_t (*call)(void *) = ocall_table_probe.table[index];
    return call(data);
}
