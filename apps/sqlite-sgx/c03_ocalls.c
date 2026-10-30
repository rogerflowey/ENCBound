/*
 * C03 host OCALLs. This file intentionally does not include Enclave_u.h: the
 * generated untrusted header declares the OCALL prototypes with the trusted
 * EDL struct stat and pulls in the other host service declarations. Keeping
 * the host definitions in a separate translation unit preserves the ordinary
 * glibc struct stat and the selected Unix-VFS host ABI.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "c03_ocalls.h"

#define CANARY_PREFIX "C03-PROTECTED-CANARY"

static int g_hostile;
static int g_phase = 1;
static uintptr_t g_canary_address;
static unsigned long g_getenv_calls[2];
static unsigned long g_hostile_getenv_calls[2];
static unsigned long g_stat_calls[2];
static unsigned long g_canary_stat_calls[2];
static unsigned long g_temp_open_calls[2];

#define BUMP(array) (array[(g_phase == 2) ? 1 : 0]++)

void c03_configure(int hostile, uintptr_t canary_address)
{
    g_hostile = hostile;
    g_canary_address = canary_address;
}

void c03_set_phase(int phase)
{
    g_phase = phase;
}

void c03_print_summary(int hostile)
{
    printf("{\"result\":\"PASS\",\"mode\":\"%s\","
           "\"getenv_calls\":%lu,\"hostile_getenv_calls\":%lu,"
           "\"stat_calls\":%lu,\"canary_stat_calls\":%lu,"
           "\"temp_open_calls\":%lu,"
           "\"phase1\":{\"getenv\":%lu,\"hostile_getenv\":%lu,"
           "\"stat\":%lu,\"canary_stat\":%lu,\"temp_open\":%lu},"
           "\"phase2\":{\"getenv\":%lu,\"hostile_getenv\":%lu,"
           "\"stat\":%lu,\"canary_stat\":%lu,\"temp_open\":%lu}}\n",
           hostile ? "hostile" : "benign",
           g_getenv_calls[0]+g_getenv_calls[1],
           g_hostile_getenv_calls[0]+g_hostile_getenv_calls[1],
           g_stat_calls[0]+g_stat_calls[1],
           g_canary_stat_calls[0]+g_canary_stat_calls[1],
           g_temp_open_calls[0]+g_temp_open_calls[1],
           g_getenv_calls[0], g_hostile_getenv_calls[0], g_stat_calls[0],
           g_canary_stat_calls[0], g_temp_open_calls[0],
           g_getenv_calls[1], g_hostile_getenv_calls[1], g_stat_calls[1],
           g_canary_stat_calls[1], g_temp_open_calls[1]);
    fflush(stdout);
}

static int is_canary_path(const char *path)
{
    return path != NULL && strstr(path, CANARY_PREFIX) != NULL;
}

int ocall_lstat(const char *p, struct stat *b, size_t size)
{
    (void)size;
    return lstat(p, b);
}

int ocall_stat(const char *p, struct stat *b, size_t size)
{
    (void)size;
    BUMP(g_stat_calls);
    if (is_canary_path(p)) {
        BUMP(g_canary_stat_calls);
        fprintf(stderr, "[c03] ocall_stat received canary path: \"%s\"\n", p);
    }
    return stat(p, b);
}

int ocall_fstat(int f, struct stat *b, size_t size)
{
    (void)size;
    return fstat(f, b);
}

int ocall_ftruncate(int f, off_t n) { return ftruncate(f, n); }
char *ocall_getcwd(char *b, size_t n) { return getcwd(b, n); }
int ocall_getpid(void) { return getpid(); }
int ocall_getuid(void) { return geteuid(); }

char *ocall_getenv(const char *n)
{
    char *r;
    BUMP(g_getenv_calls);
    if (g_hostile && n != NULL && strcmp(n, "SQLITE_TMPDIR") == 0) {
        BUMP(g_hostile_getenv_calls);
        fprintf(stderr, "[c03] hostile getenv(%s) -> %p\n", n,
                (void *)g_canary_address);
        return (char *)g_canary_address;
    }
    r = getenv(n);
    fprintf(stderr, "[c03] getenv(%s) -> %p\n", n, (void *)r);
    return r;
}

int ocall_open64(const char *p, int flags, mode_t m)
{
    if (p != NULL && strstr(p, "etilqs_") != NULL) {
        BUMP(g_temp_open_calls);
        fprintf(stderr, "[c03] temp file open: \"%s\"\n", p);
    }
    return open(p, flags, m);
}

int ocall_close(int f) { return close(f); }
off_t ocall_lseek64(int f, off_t o, int w) { return lseek(f, o, w); }
int ocall_read(int f, void *b, size_t n) { return (int)read(f, b, n); }
int ocall_write(int f, const void *b, size_t n) { return (int)write(f, b, n); }
int ocall_fsync(int f) { return fsync(f); }
int ocall_unlink(const char *p) { return unlink(p); }

int ocall_access(const char *p, int m)
{
    if (is_canary_path(p)) {
        BUMP(g_canary_stat_calls);
        fprintf(stderr, "[c03] ocall_access received canary path: \"%s\"\n", p);
    }
    return access(p, m);
}

int ocall_mkdir(const char *p, mode_t m) { return mkdir(p, m); }
int ocall_rmdir(const char *p) { return rmdir(p); }
int ocall_fchmod(int f, mode_t m) { return fchmod(f, m); }
int ocall_fchown(int f, unsigned int u, unsigned int g) { return fchown(f, u, g); }

int ocall_utimes(const char *p, void *t, size_t n)
{
    (void)n;
    return utimes(p, (const struct timeval *)t);
}

long ocall_readlink(const char *p, char *b, size_t n)
{
    return (long)readlink(p, b, n);
}

int ocall_gettimeofday(void *tv, size_t n)
{
    (void)n;
    return gettimeofday((struct timeval *)tv, NULL);
}

int ocall_localtime(long t, void *tm, size_t n)
{
    (void)n;
    time_t value = (time_t)t;
    return localtime_r(&value, (struct tm *)tm) ? 0 : -1;
}

unsigned int ocall_sleep(unsigned int s) { sleep(s); return 0; }
long ocall_time(void) { return (long)time(NULL); }
long ocall_sysconf(int n) { return sysconf(n); }

int ocall_fcntl(int fd, int cmd, void *arg, size_t size)
{
    (void)size;
    switch (cmd) {
    case F_GETFD: case F_SETFD: case F_GETFL: case F_SETFL:
    case F_GETOWN: case F_SETOWN:
#ifdef F_GETSIG
    case F_GETSIG: case F_SETSIG:
#endif
        return fcntl(fd, cmd, *(int *)arg);
    default:
        return fcntl(fd, cmd, arg);
    }
}

void ocall_print_error(const char *s)
{
    if (write(2, s, strlen(s)) < 0) { /* best effort diagnostic */ }
    if (write(2, "\n", 1) < 0) { /* best effort diagnostic */ }
}

void ocall_print_string(const char *s)
{
    if (write(1, s, strlen(s)) < 0) { /* best effort output */ }
}

void ocall_println_string(const char *s)
{
    if (write(1, s, strlen(s)) < 0) { /* best effort output */ }
    if (write(1, "\n", 1) < 0) { /* best effort output */ }
}
