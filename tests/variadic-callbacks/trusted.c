/* Test-only private SDK target for attributed data-pointer controls. */
#include <stdint.h>
static unsigned char private_byte=0x77;
uintptr_t callback_target(void) { return (uintptr_t)&private_byte; }

