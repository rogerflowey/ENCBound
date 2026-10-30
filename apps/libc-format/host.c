/* Matched SDK SIM functional oracle; no timing/hardware claim. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <wchar.h>
#include "sgx_urts.h"
#include "enclave_u.h"
static void permissions(const char *image) {
 FILE *f=fopen(image,"rb"); assert(f); Elf64_Ehdr eh; assert(fread(&eh,1,sizeof eh,f)==sizeof eh);
 Elf64_Shdr *sh=malloc(eh.e_shnum*sizeof(*sh)); assert(sh);
 assert(fseek(f,eh.e_shoff,SEEK_SET)==0);assert(fread(sh,sizeof(*sh),eh.e_shnum,f)==eh.e_shnum);
 char *names=malloc(sh[eh.e_shstrndx].sh_size);assert(names);
 assert(fseek(f,sh[eh.e_shstrndx].sh_offset,SEEK_SET)==0);assert(fread(names,1,sh[eh.e_shstrndx].sh_size,f)==sh[eh.e_shstrndx].sh_size);fclose(f);
 const char *configured=getenv("ENCBOUND_TEST_BASE");uintptr_t base=configured?strtoull(configured,0,0):0x40000000;
 unsigned verified=0;
 for(unsigned i=0;i<eh.e_shnum;i++) {
  const char *name=names+sh[i].sh_name;
  if(strcmp(name,".encbound.appdata") && strcmp(name,".encbound.apprelro") && strcmp(name,".encbound.apprw") && strcmp(name,".encbound.appbss") &&
     strcmp(name,".encbound.globalrw") && strcmp(name,".encbound.globalbss") && strcmp(name,".encbound.gcaps") && strcmp(name,".encbound.gfix"))continue;
  if(!sh[i].sh_size)continue;
  int writable=strcmp(name,".encbound.appdata") && strcmp(name,".encbound.apprelro");
  uintptr_t start=base+sh[i].sh_addr,end=start+sh[i].sh_size;
  FILE *maps=fopen("/proc/self/maps","r");assert(maps);char line[512];int found=0;
  while(fgets(line,sizeof line,maps)) { unsigned long lo,hi;char perm[5];
   if(sscanf(line,"%lx-%lx %4s",&lo,&hi,perm)==3 && start>=lo && end<=hi) {
    assert(perm[0]=='r' && (perm[1]=='w')==writable && perm[2]!='x');found=1;break;
   }
  }
  fclose(maps);assert(found);verified++;
 }
 assert(verified>=3);free(names);free(sh);fprintf(stderr,"loaded app page permissions: PASS (%u ranges)\n",verified);
}
static unsigned observations;
static unsigned record_observations;
static unsigned user_check_observations;
uintptr_t user_check_observe(char **pointer,uintptr_t expected,int action,Options options,char *copied) {
    assert((uintptr_t)pointer==expected && options.forward && !options.mutate && options.notify);
    assert(!memcmp(copied,"copy123",8));
    if(action==1) {pointer[0][0]='h';pointer[0]=pointer[1];}
    /* action 2 carries an opaque enclave capability: the host never accesses it. */
    copied[0]='!';++user_check_observations;return (uintptr_t)pointer;
}
int record_observe(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,
    Options small,FormatRecord first,FormatRecord second) {
    assert(a+b+c+d+e+f==21 && small.forward && small.mutate && small.notify);
    assert(first.words[0]==111 && second.words[0]==22 && first.ratio==1.25 && second.ratio==2.5);
    first.words[0]=999;small.mutate=false;++record_observations;return 133;
}
int format_observe(char *prefix,uint32_t *values,size_t count) {
    assert(!memcmp(prefix,"seed123",8));
    unsigned sum=0;for(size_t i=0;i<count;++i)sum+=values[i];
    prefix[0]='!';++observations;return (int)sum;
}
static int oracle(char *output,size_t cap,const char *format,const char *text,unsigned sum,int mode) {
    if(mode==2)return snprintf(output,cap,format,1,2,3,4,5,6,7,8,9,10,11,12,1.,2.,3.,4.,5.,6.,7.,8.,9.,10.);
    if(mode==3)return snprintf(output,cap,format,0.1);
    if(mode==4)return snprintf(output,cap,format,text,17,1.25);
    if(mode==5)return snprintf(output,cap,format,-8,3,text);
    if(mode==6)return snprintf(output,cap,format,L"AB",L'C');
    return snprintf(output,cap,format,text,sum,1.25);
}
int main(int argc,char **argv) {
    assert(argc==2);sgx_enclave_id_t eid;
    assert(sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL)==SGX_SUCCESS);
    permissions(argv[1]);int layout=-1;
    assert(layout_checks(eid,&layout)==SGX_SUCCESS && layout==0);
    uintptr_t bits[]={0,1,UINT64_C(1)<<48,UINT64_MAX};
    for(unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i) {
      int result=-1;
      assert(user_check_service(eid,&result,(char **)bits[i],bits[i],0)==SGX_SUCCESS && result==42);
    }
    char first[]="Abc",second[]="Bcd";char *host_args[]={first,second};int user_result=-1;
    assert(user_check_service(eid,&user_result,host_args,(uintptr_t)host_args,1)==SGX_SUCCESS);
    assert(user_result==42 && first[0]=='h' && host_args[0]==second);
    for(unsigned i=0;i<3;++i)
      assert(user_check_service(eid,&user_result,NULL,0,2)==SGX_SUCCESS && user_result==42);
    assert(user_check_observations==8);
    for(unsigned i=0;i<8;++i) {
      Options small={true,false,true};
      FormatRecord first={{11,12,13,14},{false,true,false},1.25};
      FormatRecord second={{22,23,24,25},{true,false,true},2.5};
      uint64_t output=0;int result=-999;
      assert(record_service(eid,&result,1,2,3,4,5,6,small,first,second,&output)==SGX_SUCCESS);
      assert(result==42 && output==133 && first.words[0]==11 && second.words[0]==22 && !small.mutate);
    }
    assert(record_observations==8);
    const char *formats[]={"%s:%u:%.3f","[%s|%08u|%.7g]",
      "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d:%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f",
      "%.512f","%2$d:%1$s:%3$.2f","%*.*s","%ls:%lc","%Lf","%1$Lf","%1$*2$Lf"};
    size_t capacities[]={0,1,8,16,64,2048};unsigned jobs=0;
    for(unsigned repetition=0;repetition<2;++repetition)
    for(int mode=0;mode<10;++mode)for(unsigned c=0;c<6;++c)for(unsigned option=0;option<2;++option) {
      size_t cap=capacities[c];char out[2048],expected[2048],text[16]="hello";
      memset(out,0,sizeof(out));memcpy(out,"seed123",8);memset(expected,0,sizeof(expected));
      bool ok=false;uint32_t values[]={7,11};Options opts={option,option,option};int result=-999;
      sgx_status_t status=format_service(eid,&result,(char *)formats[mode],opts,text,values,2,&ok,out,cap,mode);
      assert(status==SGX_SUCCESS);assert(!strcmp(text,"hello"));
      if(mode>=7){assert(result==-1 && !ok);if(cap)assert(out[0]==0);}
      else {
        int want=oracle(expected,cap,formats[mode],option?"Zello":"hello",18,mode);
        if(result!=want || !ok || (cap && strcmp(out,expected))) {
          fprintf(stderr,"mode=%d cap=%zu option=%u result=%d expected=%d output=%s expected=%s\n",mode,cap,option,result,want,out,expected);abort();
        }
      }
      ++jobs;
    }
    /* Intel byte-count overflow rejects before allocation; next call recovers. */
    for(unsigned i=0;i<4;++i) {
      char out[16]="seed123",text[]="x";uint32_t values[2]={1,2};bool ok=false;int result;
      Options opts={0,0,0};
      assert(format_service(eid,&result,"%s:%u:%.3f",opts,text,values,SIZE_MAX/4+1,&ok,out,16,0)==SGX_ERROR_INVALID_PARAMETER);
      assert(format_service(eid,&result,"%s:%u:%.3f",opts,text,values,2,&ok,out,16,0)==SGX_SUCCESS && ok);
      ++jobs;
    }
    assert(sgx_destroy_enclave(eid)==SGX_SUCCESS);
    printf("FORMAT/EDL SDK SIM PASS jobs=%u observations=%u record_jobs=8 record_observations=%u user_check_jobs=8 user_check_observations=%u\n",jobs,observations,record_observations,user_check_observations);
}
