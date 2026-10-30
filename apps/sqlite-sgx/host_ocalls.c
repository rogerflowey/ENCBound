#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int ocall_lstat(const char *p, struct stat *b){return lstat(p,b);}
int ocall_stat(const char *p, struct stat *b){return stat(p,b);}
int ocall_fstat(int f, struct stat *b){return fstat(f,b);}
int ocall_ftruncate(int f, off_t n){return ftruncate(f,n);}
char *ocall_getcwd(char *b,size_t n){return getcwd(b,n);}
int ocall_getpid(void){return getpid();}
int ocall_getuid(void){return geteuid();}
char *ocall_getenv(const char *n){return getenv(n);}
int ocall_open64(const char *p,int flags,mode_t m){return open(p,flags,m);}
int ocall_close(int f){return close(f);}
off_t ocall_lseek64(int f,off_t o,int w){return lseek(f,o,w);}
int ocall_read(int f,void *b,size_t n){return (int)read(f,b,n);}
int ocall_write(int f,const void *b,size_t n){return (int)write(f,b,n);}
int ocall_fsync(int f){return fsync(f);}
int ocall_unlink(const char *p){return unlink(p);}
int ocall_access(const char *p,int m){return access(p,m);}
int ocall_mkdir(const char *p,mode_t m){return mkdir(p,m);}
int ocall_rmdir(const char *p){return rmdir(p);}
int ocall_fchmod(int f,mode_t m){return fchmod(f,m);}
int ocall_fchown(int f,unsigned int u,unsigned int g){return fchown(f,u,g);}
int ocall_utimes(const char *p,void *t,size_t n){(void)n;return utimes(p,(const struct timeval *)t);}
long ocall_readlink(const char *p,char *b,size_t n){return (long)readlink(p,b,n);}
int ocall_gettimeofday(void *tv,size_t n){(void)n;return gettimeofday((struct timeval *)tv,NULL);}
int ocall_localtime(long t,void *tm,size_t n){(void)n;time_t value=(time_t)t;return localtime_r(&value,(struct tm *)tm)?0:-1;}
unsigned int ocall_sleep(unsigned int s){sleep(s);return 0;}
long ocall_time(void){return (long)time(NULL);}
long ocall_sysconf(int n){return sysconf(n);}

int ocall_fcntl(int fd,int cmd,void *arg,size_t size)
{
    (void)size;
    switch(cmd) {
    case F_GETFD: case F_SETFD: case F_GETFL: case F_SETFL:
    case F_GETOWN: case F_SETOWN:
#ifdef F_GETSIG
    case F_GETSIG: case F_SETSIG:
#endif
        return fcntl(fd,cmd,*(int *)arg);
    default:
        return fcntl(fd,cmd,arg);
    }
}

void ocall_print_error(const char *s){write(2,s,strlen(s));write(2,"\n",1);}
void ocall_print_string(const char *s){write(1,s,strlen(s));}
void ocall_println_string(const char *s){write(1,s,strlen(s));write(1,"\n",1);}
