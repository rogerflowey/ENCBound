#ifndef APPLICATION_FORMAT_API_H
#define APPLICATION_FORMAT_API_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct Options { bool forward; bool mutate; bool notify; } Options;
typedef struct FormatRecord { uint64_t words[4]; Options options; double ratio; } FormatRecord;
#endif
