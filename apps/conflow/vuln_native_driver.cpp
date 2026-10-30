/* Uninstrumented native driver for the ConFlow hostile-shape control.
 *
 * The application object is the same extracted upstream softmax body compiled
 * through tools/encbound-cc.sh. This driver supplies the real checked runtime
 * over tests/fake_platform.c, runs the application on the fake protected stack
 * (so its local arrays are representative), and catches encbound_abort so the
 * profile/error category can be reported.
 *
 * The sgx_read_rand stand-in decodes a capability before filling randomness;
 * it is a control harness, not an SDK service implementation.
 */
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <ucontext.h>

#include "encbound_common.h"
#include "encbound_runtime.h"

extern "C" {
extern int fake_abort_code;
extern jmp_buf fake_abort_env;
extern int fake_abort_active;
unsigned long encbound_enclave_base(void);
void ecall_softmax(float *, int, int, int, float *);
void ecall_softmax_grad(float *, float *, int, int, int, float *);
}

static ucontext_t caller, app;
static float input[320], grad[320], output[514];
static int n, m, c, gradient;

static void enter(void)
{
    if (gradient) {
        ecall_softmax_grad(input, grad, n, m, c, output);
    } else {
        ecall_softmax(input, n, m, c, output);
    }
}

extern "C" unsigned sgx_read_rand(unsigned char *p, size_t length)
{
    uintptr_t raw = 0;
    if (encbound_check((uintptr_t)p, length, ENCBOUND_ACCESS_WRITE, &raw) !=
        ENCBOUND_OK) {
        return 1;
    }
    return getrandom((unsigned char *)raw, length, 0) == (ssize_t)length ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <softmax|softmax_grad> N M C\n", argv[0]);
        return 2;
    }
    gradient = !strcmp(argv[1], "softmax_grad");
    n = atoi(argv[2]);
    m = atoi(argv[3]);
    c = atoi(argv[4]);
    if (encbound_runtime_init_with_key(11, 22) != ENCBOUND_OK) {
        return 90;
    }
    for (int i = 0; i < 320; ++i) {
        input[i] = (float)((i % 17) - 8) * 0.125f;
        grad[i] = (float)((i % 13) - 6) * 0.25f;
    }
    memset(output, 0, sizeof output);

    if (getcontext(&app) != 0) {
        return 91;
    }
    app.uc_stack.ss_sp = (void *)(encbound_enclave_base() + 0x100000);
    app.uc_stack.ss_size = 0x100000;
    app.uc_link = &caller;
    makecontext(&app, enter, 0);

    fake_abort_active = 1;
    if (setjmp(fake_abort_env) == 0) {
        swapcontext(&caller, &app);
        printf("ACCEPTED out0=%.9g\n", output[0]);
    } else {
        printf("ABORT code=%d\n", fake_abort_code);
    }
    return 0;
}
