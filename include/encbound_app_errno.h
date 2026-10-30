/* Serial application-libc errno ABI. These functions are application code;
 * neither the cell nor its pointer refers to SDK/runtime TLS. */
#ifndef ENCBOUND_APP_ERRNO_H
#define ENCBOUND_APP_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif
int *__encbound_app_errno_location(void);
void __encbound_app_errno_store(int value);
#ifdef __cplusplus
}
#endif

#endif
