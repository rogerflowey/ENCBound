/* Both libc accessor spellings in a C++ dependency called by a C app unit. */
#include <errno.h>
extern "C" int errno_dependency_read(void) { return *__errno(); }
extern "C" int errno_dependency_write(int value)
{
    *__errno_location() = value;
    return errno;
}
