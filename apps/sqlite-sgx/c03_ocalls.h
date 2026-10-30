#ifndef C03_OCALLS_H
#define C03_OCALLS_H

#include <stdint.h>

void c03_configure(int hostile, uintptr_t canary_address);
void c03_set_phase(int phase);
void c03_print_summary(int hostile);

#endif
