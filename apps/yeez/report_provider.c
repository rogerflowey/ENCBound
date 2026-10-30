/* Application-owned report snapshot; SDK's private static report never escapes. */
#include "full_services.h"
static sgx_report_t application_report;
const sgx_report_t *yeez_self_report(void)
{
    if(yeez_report_copy(&application_report)!=SGX_SUCCESS)return NULL;
    return &application_report;
}
