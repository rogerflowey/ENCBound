#ifndef ENCBOUND_TEST_HARNESS_H
#define ENCBOUND_TEST_HARNESS_H

#include <stdio.h>

static int g_checks;
static int g_failures;

#define CHECK(cond)                                                            \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            g_failures++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);             \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        long long va = (long long)(a);                                         \
        long long vb = (long long)(b);                                         \
        g_checks++;                                                            \
        if (va != vb) {                                                        \
            g_failures++;                                                      \
            printf("FAIL %s:%d: %s=%lld != %s=%lld\n", __FILE__, __LINE__, #a, \
                   va, #b, vb);                                                \
        }                                                                      \
    } while (0)

#define TEST_SUMMARY(name)                                                     \
    (printf("%-22s %3d checks, %d failures\n", (name), g_checks, g_failures),  \
     g_failures == 0 ? 0 : 1)

#endif /* ENCBOUND_TEST_HARNESS_H */
