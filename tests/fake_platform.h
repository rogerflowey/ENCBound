#ifndef ENCBOUND_FAKE_PLATFORM_H
#define ENCBOUND_FAKE_PLATFORM_H

#include <setjmp.h>

extern int fake_abort_code;
extern jmp_buf fake_abort_env;
extern int fake_abort_active;

#endif /* ENCBOUND_FAKE_PLATFORM_H */
