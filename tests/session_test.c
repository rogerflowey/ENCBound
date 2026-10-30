/*
 * ENCBound restart - native session/lifecycle test for shared boundary support
 * (docs/legacy/steps/09-original-api-and-sessions.md).
 *
 * Exercises the small handwritten trusted support directly against the checked
 * runtime and the fake platform:
 *
 *   - the admission gate is serial: a nested/overlapping admit is refused and a
 *     release restores idle;
 *   - a failed session is terminal and can never be re-entered;
 *   - initialize-once is idempotent and does not regenerate the runtime key;
 *   - a keyed runtime init refuses a second key and the key is stable;
 *   - a live protected allocation survives unrelated gate transitions.
 *
 * Each case runs in a forked child so module state and the protected heap start
 * fresh. This is native evidence about the trusted seam, not the enclave build.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "encbound_common.h"
#include "encbound_runtime.h"
#include "encbound_internal.h"
#include "boundary_support.h"

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "  CHECK FAILED: %s (line %d)\n", (msg), __LINE__);\
            _exit(1);                                                          \
        }                                                                      \
    } while (0)

#define KEY0 0x0706050403020100ull
#define KEY1 0x0f0e0d0c0b0a0908ull
#define KEY2 0x1716151413121110ull
#define KEY3 0x1f1e1d1c1b1a1918ull

static void case_admit_release_cycles(void)
{
    CHECK(encbound_boundary_admit() == 0, "first admit");
    CHECK(encbound_boundary_admit() != 0, "nested admit refused");
    encbound_boundary_release();
    CHECK(encbound_boundary_admit() == 0, "admit after release");
    encbound_boundary_release();
}

static void case_fail_is_terminal(void)
{
    CHECK(encbound_boundary_admit() == 0, "admit");
    encbound_boundary_fail();
    /* A release must not resurrect a terminal session. */
    encbound_boundary_release();
    CHECK(encbound_boundary_admit() != 0, "terminal session refuses entry");
}

static void case_initialize_once(void)
{
    CHECK(encbound_boundary_admit() == 0, "admit");
    CHECK(encbound_boundary_initialize() == 0, "first initialize");
    CHECK(encbound_boundary_initialize() == 0, "initialize is idempotent");
    encbound_boundary_release();
}

static void case_keyed_init_stable(void)
{
    uint64_t k0;
    CHECK(encbound_runtime_init_with_key(KEY0, KEY1) == ENCBOUND_OK,
          "keyed init");
    k0 = encbound_key0();
    CHECK(k0 == KEY0 && encbound_key1() == KEY1, "key is the supplied key");
    /* Initialize-once must reuse the already-initialized runtime. */
    CHECK(encbound_boundary_admit() == 0, "admit");
    CHECK(encbound_boundary_initialize() == 0, "initialize over keyed runtime");
    CHECK(encbound_key0() == k0, "initialize does not regenerate the key");
    CHECK(encbound_runtime_init() == ENCBOUND_OK, "plain init is idempotent");
    CHECK(encbound_key0() == k0, "plain init does not regenerate the key");
    CHECK(encbound_runtime_init_with_key(KEY2, KEY3) == ENCBOUND_ERR_STATE,
          "second keyed init refused");
    CHECK(encbound_key0() == k0, "refused key does not overwrite the key");
    encbound_boundary_release();
}

static void case_live_allocation_survives(void)
{
    uint8_t *w;
    const uint8_t *r;
    size_t i;
    void *live;
    CHECK(encbound_boundary_admit() == 0, "admit");
    CHECK(encbound_boundary_initialize() == 0, "initialize");
    live = encbound_boundary_alloc(64u);
    CHECK(live != NULL, "allocate");
    w = encbound_boundary_write(live, 64u);
    for (i = 0; i < 64u; ++i) {
        w[i] = (uint8_t)(0x40u + i);
    }
    encbound_boundary_release();

    /* An unrelated gate cycle must not disturb the live allocation. */
    CHECK(encbound_boundary_admit() == 0, "re-admit");
    CHECK(encbound_boundary_initialize() == 0, "re-initialize");
    r = encbound_boundary_read(live, 64u);
    for (i = 0; i < 64u; ++i) {
        CHECK(r[i] == (uint8_t)(0x40u + i), "live content intact");
    }
    encbound_boundary_free(live);
    encbound_boundary_release();
}

static void case_strnlen_cap(void)
{
    static char buf[8] = { 'a', 'b', 'c', '\0', 'd', 'e', 'f', 'g' };
    CHECK(encbound_boundary_strnlen(buf, sizeof(buf)) == 3u, "strnlen finds NUL");
    CHECK(encbound_boundary_strnlen("abcdefg", 3u) == (size_t)-1,
          "strnlen respects cap");
    CHECK(encbound_boundary_strnlen(NULL, 4u) == (size_t)-1, "strnlen NULL");
}

struct test_case {
    const char *name;
    void (*fn)(void);
};

static const struct test_case cases[] = {
    { "admit_release_cycles", case_admit_release_cycles },
    { "fail_is_terminal", case_fail_is_terminal },
    { "initialize_once", case_initialize_once },
    { "keyed_init_stable", case_keyed_init_stable },
    { "live_allocation_survives", case_live_allocation_survives },
    { "strnlen_cap", case_strnlen_cap },
};

int main(void)
{
    size_t i;
    int failures = 0;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        pid_t pid = fork();
        int status = 0;
        if (pid < 0) {
            fprintf(stderr, "fork failed\n");
            return 2;
        }
        if (pid == 0) {
            cases[i].fn();
            _exit(0);
        }
        if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
            fprintf(stderr, "FAIL: %s\n", cases[i].name);
            failures++;
        } else {
            printf("pass: %s\n", cases[i].name);
        }
    }

    if (failures != 0) {
        printf("SESSION TEST FAIL (%d/%zu cases)\n", failures,
               sizeof(cases) / sizeof(cases[0]));
        return 1;
    }
    printf("SESSION TEST PASS (%zu cases)\n", sizeof(cases) / sizeof(cases[0]));
    return 0;
}
