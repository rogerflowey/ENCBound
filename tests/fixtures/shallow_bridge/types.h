#ifndef SHALLOW_BRIDGE_TYPES_H
#define SHALLOW_BRIDGE_TYPES_H
#include <stdint.h>
typedef struct Flexible { uint32_t n; unsigned char data[]; } Flexible;
typedef struct Opaque Opaque;
typedef struct Shallow { char *host; char *owned; uintptr_t token; } Shallow;
typedef int *IntPtr;
typedef int IntArray[3];
#endif
