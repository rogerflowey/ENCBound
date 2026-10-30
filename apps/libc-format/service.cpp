#include "api.h"
#include "sgx_error.h"
#include <stdio.h>
extern "C" int format_forward(char *,size_t,const char *,...);
extern "C" sgx_status_t format_observe(int *,char *,uint32_t *,size_t);
extern "C" sgx_status_t record_observe(int *,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,
                                      Options,FormatRecord,FormatRecord);
extern "C" sgx_status_t user_check_observe(uintptr_t *,char **,uintptr_t,int,Options,char *);
extern "C" int user_check_service(char **host,uintptr_t expected,int action) {
    char copied[8]="copy123",local[16];
    if(action==2) { local[0]='q';host=(char **)local;expected=(uintptr_t)local; }
    uintptr_t echo=0;Options options={true,false,true};
    if(user_check_observe(&echo,host,expected,action,options,copied)!=SGX_SUCCESS ||
       echo!=expected || copied[0]!='!')return -1;
    if(action==1 && host[0][0]!='B')return -2;
    if(action==2) {
        char *same=(char *)echo;
        if(same[0]!='q')return -3;
        same[0]='r';if(local[0]!='r')return -4;
    }
    return 42;
}
extern "C" int record_service(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,
    Options small,FormatRecord first,FormatRecord second,uint64_t *output) {
    if(a+b+c+d+e+f!=21 || !small.forward || small.mutate || !small.notify ||
       first.words[0]!=11 || second.words[0]!=22 || first.ratio!=1.25 || second.ratio!=2.5) return -1;
    first.words[0]+=100;small.mutate=true;
    int observed=0;
    if(record_observe(&observed,a,b,c,d,e,f,small,first,second)!=SGX_SUCCESS || observed!=133) return -2;
    if(first.words[0]!=111 || second.words[0]!=22 || !small.mutate) return -3;
    *output=first.words[0]+second.words[0];return 42;
}
extern "C" int format_service(char *format, Options options, char *text,
    uint32_t *values,size_t count,bool *ok,char *output,size_t capacity,int mode) {
    if(count!=2) return -96;
    unsigned sum=values[0]+values[1];
    if(options.mutate && text && text[0]) text[0]='Z';
    if(options.notify && capacity>=8) {
        int observed=0;
        if(format_observe(&observed,output,values,count)!=0 || observed!=(int)sum)
            return -99;
        if(output[0]!='!') return -98;
    }
    int result;
    if(mode==1) result=format_forward(output,capacity,format,text,sum,1.25);
    else if(mode==2) result=snprintf(output,capacity,format,
        1,2,3,4,5,6,7,8,9,10,11,12,1.,2.,3.,4.,5.,6.,7.,8.,9.,10.);
    else if(mode==3) result=snprintf(output,capacity,format,0.1);
    else if(mode==4) result=snprintf(output,capacity,format,text,17,1.25);
    else if(mode==5) {
        result=snprintf(output,capacity,format,-8,3,text);
    } else if(mode==6) {
        wchar_t wide[]={L'A',L'B',0};result=snprintf(output,capacity,format,wide,L'C');
    /* No long-double operand: the dynamic L format must reject before retrieval. */
    } else if(mode>=7) result=options.forward ? format_forward(output,capacity,format,1.25,8)
                                            : snprintf(output,capacity,format,1.25,8);
    else result=options.forward ? format_forward(output,capacity,format,text,sum,1.25)
                                 : snprintf(output,capacity,format,text,sum,1.25);
    *ok=result>=0;
    return result;
}
