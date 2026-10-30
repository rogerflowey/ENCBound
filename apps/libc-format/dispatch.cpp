#include <stdarg.h>
#include <stdio.h>
extern "C" int format_forward(char *out, size_t capacity, const char *format, ...) {
    va_list original, copy;
    va_start(original,format);
    va_copy(copy,original);
    int result=vsnprintf(out,capacity,format,copy);
    va_end(copy);
    va_end(original);
    return result;
}
