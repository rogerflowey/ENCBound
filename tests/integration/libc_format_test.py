#!/usr/bin/env python3
"""Selected libc: real native checks and terminal source/dest/format/%n controls."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--library-root',type=Path,default=R/'build/libc-format')
p.add_argument('--build',type=Path,default=R/'build/integration/libc-format')
a=p.parse_args();B=a.build.resolve();B.mkdir(parents=True,exist_ok=True)
(B/'harness.c').write_text(r'''
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
#include "fake_platform.h"
int test_formatter(unsigned char *,int);
static ucontext_t caller,app;
static unsigned char *target;
static int mode,result;
static void enter(void){result=test_formatter(target,mode);}
static void execute(void){
 assert(getcontext(&app)==0);app.uc_stack.ss_sp=(void *)(encbound_enclave_base()+0x100000);
 app.uc_stack.ss_size=0x100000;app.uc_link=&caller;makecontext(&app,enter,0);
 assert(swapcontext(&caller,&app)==0);
}
int main(void){
 assert(encbound_runtime_init_with_key(11,22)==0);
 unsigned char *raw;
#ifdef PROTECTED
 target=encbound_malloc(16);assert(target);
 raw=(void *)encbound_require((uintptr_t)target,16,ENCBOUND_ACCESS_WRITE);
#else
 raw=target=(void *)(encbound_enclave_base()+0x1000000);
#endif
 memset(raw,0x61,16);mode=0;
 fake_abort_active=1;
 if(setjmp(fake_abort_env)){fprintf(stderr,"unexpected initial rejection: %d\n",fake_abort_code);return 1;}
 execute();fake_abort_active=0;
 assert(result==1 && !strcmp((char *)raw,"ok:7:1.25"));
#ifdef PROTECTED
 unsigned char *valid=target;
 for(int c=1;c<=6;++c){
  if(c==4)continue; /* Intel deliberately terminates on %n; checked below. */
#ifndef ENCBOUND_MAC27
  if(c==6)continue;
#endif
  pid_t child=fork();assert(child>=0);
  if(!child){
   unsigned char *trusted=(void *)encbound_enclave_base();*trusted=0x77;
   target=c==5?valid:c==6?(void *)((uintptr_t)valid^(UINT64_C(1)<<32)):trusted;
   unsigned char before[16];memcpy(before,raw,16);mode=c;fake_abort_active=1;
   if(!setjmp(fake_abort_env)){execute();_exit(2);}
   int want=c==5?ENCBOUND_ERR_RANGE:c==6?ENCBOUND_ERR_TAG:ENCBOUND_ERR_POLICY;
   if(fake_abort_code!=want || *trusted!=0x77 || memcmp(before,raw,16)){
     fprintf(stderr,"formatter control=%d expected=%d observed=%d\n",c,want,fake_abort_code);_exit(3);
   }
   _exit(0);
  }
  int status;assert(waitpid(child,&status,0)==child);
  assert(WIFEXITED(status) && WEXITSTATUS(status)==0);
 }
 encbound_free(valid);
#endif
 /* Preserve the SDK's deliberate terminal %n policy in every profile. */
 pid_t terminal=fork();assert(terminal>=0);
 if(!terminal){mode=4;execute();_exit(2);}
 int terminal_status;assert(waitpid(terminal,&terminal_status,0)==terminal);
 assert(WIFSIGNALED(terminal_status) && WTERMSIG(terminal_status)==SIGABRT);
 puts("SELECTED FORMATTER NATIVE PASS");
}
''')
commands=[];rows=[]
def run(cmd,name,env=None,good=True):
 cmd=list(map(str,cmd));p=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=60)
 (B/(name+'.log')).write_text(p.stdout+p.stderr)
 commands.append(dict(command=cmd,returncode=p.returncode,log=name+'.log'))
 assert (p.returncode==0)==good, (name,p.stdout,p.stderr)
 return p
for profile in ('BASELINE','RADIX_ONLY','MAC27'):
 lib=a.library_root/profile;record=json.loads((lib/'build.json').read_text())
 for cg in ('O0','O2'):
  name=profile+'-'+cg;obj=B/(name+'.o')
  env=dict(os.environ,ENCBOUND_PROFILE=profile,ENCBOUND_APP_ERRNO='1',ENCBOUND_VARIADICS='1',ENCBOUND_CXX_ALLOCATIONS='1',
           ENCBOUND_ADMITTED=str(lib/'admitted.txt'),ENCBOUND_CODEGEN_OPT='-'+cg)
  run([R/'tools/encbound-cc.sh',R/'apps/libc-format/native_cases.c',obj,*record['flags']],name+'-compile',env)
  flags=['-DPROTECTED'] if profile!='BASELINE' else []
  if profile=='MAC27':flags+=['-DENCBOUND_MAC27']
  runtime=[R/'runtime'/(n+'.c') for n in ('runtime','siphash','capability','allocator','allocations','adapters','cxx_services')]
  exe=B/name
  run(['clang-21','-O2',*flags,*['-I'+str(R/d) for d in ('include','runtime','tests')],
       B/'harness.c',obj,*record['objects'],R/'tests/fake_platform.c',*runtime,'-lm','-o',exe],name+'-link')
  run([exe],name+'-execute')
  rows.append(dict(profile=profile,codegen=cg,scope='native fake platform; actual application stack; real runtime',
                   terminal_controls=0 if profile=='BASELINE' else 5 if profile=='MAC27' else 4,
                   sdk_percent_n_terminal_controls=1,
                   executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
 # Private ABI ownership: raw SDK libc must not satisfy a selected-library reference.
 p=run(['clang-21',obj,'-o',B/(profile+'-raw-fallback')],profile+'-raw-fallback',good=False)
 assert '__encbound_va_' in p.stderr
(B/'results.json').write_text(json.dumps(dict(rows=rows,commands=commands),indent=2)+'\n')
print('SELECTED LIBC FORMAT NATIVE PASS:',len(rows),'execution rows, 18 protection controls, 6 SDK %n terminal controls, 3 raw-fallback link rejections')
