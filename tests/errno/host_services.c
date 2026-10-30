/* Original test host services. INT_MIN deliberately leaves host errno alone. */
#include <assert.h>
#include <errno.h>
#include <limits.h>

static int service_errno;
void errno_host_prepare(int value) { errno = value; }
int errno_host_value(void) { return errno; }
int errno_host_captured(void) { return service_errno; }
int errno_exchange(int value, int result, int *words)
{
    assert(words[0] == 11 && words[1] == 22);
    words[0] = 33; words[1] = 44;
    if (value != INT_MIN) errno = value;
    service_errno=errno;
    return result;
}
void errno_void(int value) { if (value != INT_MIN) errno = value; service_errno=errno; }
void errno_naked(void) { service_errno=errno; }
int errno_plain(int value, int result)
{
    errno = value;
    service_errno=errno;
    return result;
}
