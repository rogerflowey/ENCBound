#include <stddef.h>

/* Application-owned serial replacements for the two libc symbols needed by
 * this selected SQLite closure. They are compiled and instrumented as normal
 * application code; no SDK errno/TLS or raw library state is exposed. */
int strncmp(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i=0; i<n; ++i) {
        unsigned char x=(unsigned char)a[i], y=(unsigned char)b[i];
        if (x!=y) return x<y ? -1 : 1;
        if (!x) return 0;
    }
    return 0;
}

static char error_buffer[64];
char *strerror(int number)
{
    const char *text="Unknown error";
    switch(number) {
    case 0: text="Success"; break;
    case 2: text="No such file or directory"; break;
    case 9: text="Bad file descriptor"; break;
    case 11: text="Resource temporarily unavailable"; break;
    case 13: text="Permission denied"; break;
    case 17: text="File exists"; break;
    case 28: text="No space left on device"; break;
    case 30: text="Read-only file system"; break;
    case 38: text="Function not implemented"; break;
    }
    size_t i=0;
    while (text[i] && i+1<sizeof error_buffer) { error_buffer[i]=text[i]; ++i; }
    error_buffer[i]='\0';
    return error_buffer;
}
