#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define DO_NOT_REDEFINE_FOR_OCALL
#include "Enclave_t.h"
#ifndef O_TMPFILE
#define O_TMPFILE 0
#endif

static void report_failure(const char *name)
{
    ocall_print_error(name);
}

/* C03 hostile-ingress probe. This is one writable application global, so the
 * placement pass classifies it as PROTECTED application data. The C03 host
 * returns its address from ocall_getenv for SQLITE_TMPDIR. A stock bridge
 * copies the string back through the later [in,string] ocall_stat; the checked
 * bridge must reject the raw protected address before any host callback. */
char encbound_c03_canary[64] = "C03-PROTECTED-CANARY-8f4d2a";

int open64(const char *path, int flags, ...)
{
    mode_t mode=0;
    if ((flags & O_CREAT) || ((flags & O_TMPFILE)==O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode=(mode_t)va_arg(ap, int); va_end(ap);
    }
    int result=-1; if (ocall_open64(&result,path,flags,mode)!=SGX_SUCCESS) report_failure("open64");
    return result;
}
off_t lseek64(int fd, off_t offset, int whence)
{ off_t result=-1; if(ocall_lseek64(&result,fd,offset,whence)!=SGX_SUCCESS)report_failure("lseek64"); return result; }
int close(int fd)
{ int result=-1; if(ocall_close(&result,fd)!=SGX_SUCCESS)report_failure("close"); return result; }
int fsync(int fd)
{ int result=-1; if(ocall_fsync(&result,fd)!=SGX_SUCCESS)report_failure("fsync"); return result; }
ssize_t read(int fd, void *buf, size_t count)
{ int result=-1; if(ocall_read(&result,fd,buf,count)!=SGX_SUCCESS)report_failure("read"); return result; }
ssize_t write(int fd, const void *buf, size_t count)
{ int result=-1; if(ocall_write(&result,fd,buf,count)!=SGX_SUCCESS)report_failure("write"); return result; }
int access(const char *path, int mode)
{ int result=-1; if(ocall_access(&result,path,mode)!=SGX_SUCCESS)report_failure("access"); return result; }
int unlink(const char *path)
{ int result=-1; if(ocall_unlink(&result,path)!=SGX_SUCCESS)report_failure("unlink"); return result; }
int mkdir(const char *path, mode_t mode)
{ int result=-1; if(ocall_mkdir(&result,path,mode)!=SGX_SUCCESS)report_failure("mkdir"); return result; }
int rmdir(const char *path)
{ int result=-1; if(ocall_rmdir(&result,path)!=SGX_SUCCESS)report_failure("rmdir"); return result; }
int fchmod(int fd, mode_t mode)
{ int result=-1; if(ocall_fchmod(&result,fd,mode)!=SGX_SUCCESS)report_failure("fchmod"); return result; }
int fchown(int fd, uid_t owner, gid_t group)
{ int result=-1; if(ocall_fchown(&result,fd,owner,group)!=SGX_SUCCESS)report_failure("fchown"); return result; }
int sgx_lstat(const char *path, struct stat *buf)
{ int result=-1; if(ocall_lstat(&result,path,buf,sizeof *buf)!=SGX_SUCCESS)report_failure("lstat"); return result; }
int sgx_stat(const char *path, struct stat *buf)
{ int result=-1; if(ocall_stat(&result,path,buf,sizeof *buf)!=SGX_SUCCESS)report_failure("stat"); return result; }
int sgx_fstat(int fd, struct stat *buf)
{ int result=-1; if(ocall_fstat(&result,fd,buf,sizeof *buf)!=SGX_SUCCESS)report_failure("fstat"); return result; }
int sgx_ftruncate(int fd, off_t length)
{ int result=-1; if(ocall_ftruncate(&result,fd,length)!=SGX_SUCCESS)report_failure("ftruncate"); return result; }
char *getcwd(char *buf, size_t size)
{ char *result=NULL; if(ocall_getcwd(&result,buf,size)!=SGX_SUCCESS)report_failure("getcwd"); return result; }
pid_t getpid(void)
{ int result=-1; if(ocall_getpid(&result)!=SGX_SUCCESS)report_failure("getpid"); return result; }
uid_t geteuid(void)
{ int result=-1; if(ocall_getuid(&result)!=SGX_SUCCESS)report_failure("geteuid"); return result; }
char *getenv(const char *name)
{ char *result=NULL; if(ocall_getenv(&result,name)!=SGX_SUCCESS)report_failure("getenv"); return result; }
ssize_t readlink(const char *path, char *buf, size_t count)
{ long result=-1; if(ocall_readlink(&result,path,buf,count)!=SGX_SUCCESS)report_failure("readlink"); return (ssize_t)result; }
int utimes(const char *path, const struct timeval times[2])
{ int result=-1; if(ocall_utimes(&result,path,(void *)times,sizeof times[0]*2)!=SGX_SUCCESS)report_failure("utimes"); return result; }
int gettimeofday(struct timeval *tv, void *tz)
{ (void)tz; int result=-1; if(ocall_gettimeofday(&result,tv,sizeof *tv)!=SGX_SUCCESS)report_failure("gettimeofday"); return result; }
time_t time(time_t *out)
{ long result=0; if(ocall_time(&result)!=SGX_SUCCESS)report_failure("time"); if(out)*out=(time_t)result; return (time_t)result; }
unsigned int sleep(unsigned int seconds)
{ unsigned int result=seconds; if(ocall_sleep(&result,seconds)!=SGX_SUCCESS)report_failure("sleep"); return result; }
long sysconf(int name)
{ long result=-1; if(ocall_sysconf(&result,name)!=SGX_SUCCESS)report_failure("sysconf"); return result; }
struct tm *localtime(const time_t *value)
{
    static struct tm result;
    long t=value?(long)*value:0;
    int status=-1;
    if(ocall_localtime(&status,t,&result,sizeof result)!=SGX_SUCCESS || status!=0)report_failure("localtime");
    return &result;
}

static int fcntl_integer_command(int cmd)
{
    switch(cmd) {
    case F_GETFD: case F_SETFD: case F_GETFL: case F_SETFL:
    case F_GETOWN: case F_SETOWN:
#ifdef F_GETSIG
    case F_GETSIG: case F_SETSIG:
#endif
        return 1;
    default: return 0;
    }
}
static int fcntl_lock_command(int cmd)
{ return cmd==F_GETLK || cmd==F_SETLK || cmd==F_SETLKW; }

static int fcntl_dispatch(int fd, int cmd, va_list *ap)
{
    int result=-1;
    if (fcntl_integer_command(cmd)) {
        int argument=va_arg(*ap,int);
        if(ocall_fcntl(&result,fd,cmd,&argument,sizeof argument)!=SGX_SUCCESS)report_failure("fcntl");
    } else if (fcntl_lock_command(cmd)) {
        struct flock *caller=va_arg(*ap,struct flock *);
        struct flock argument=*caller;
        if(ocall_fcntl(&result,fd,cmd,&argument,sizeof argument)!=SGX_SUCCESS)report_failure("fcntl");
        if(cmd==F_GETLK && result==0) *caller=argument;
    } else {
        void *argument=va_arg(*ap,void *);
        size_t size=sizeof(void *);
        if(ocall_fcntl(&result,fd,cmd,argument,size)!=SGX_SUCCESS)report_failure("fcntl");
    }
    return result;
}

int fcntl(int fd, int cmd, ...)
{
    va_list ap; va_start(ap,cmd);
    int result=fcntl_dispatch(fd,cmd,&ap);
    va_end(ap); return result;
}

/* SQLite's large-file feature-test macros make this definition fcntl64. */
int fcntl64(int fd, int cmd, ...)
{
    va_list ap; va_start(ap,cmd);
    int result=fcntl_dispatch(fd,cmd,&ap);
    va_end(ap); return result;
}

/* Memory mapping is intentionally disabled by the selected SQLite build. */
void *mmap64(void *address,size_t length,int prot,int flags,int fd,off_t offset)
{ (void)address;(void)length;(void)prot;(void)flags;(void)fd;(void)offset; errno=ENOSYS; return MAP_FAILED; }
int munmap(void *address,size_t length) { (void)address;(void)length; errno=ENOSYS; return -1; }
void *mremap(void *old_address,size_t old_size,size_t new_size,int flags,...)
{ (void)old_address;(void)old_size;(void)new_size;(void)flags; errno=ENOSYS; return MAP_FAILED; }

