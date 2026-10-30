/* Runs on the real alternate application stack in the native harness. */
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
int test_formatter(unsigned char *target,int mode) {
    char output[256];
    if(mode==1) return snprintf((char *)target,16,"test");
    if(mode==2 || mode==6) return snprintf(output,sizeof(output),"%s",target);
    if(mode==3) return snprintf(output,sizeof(output),(char *)target,1);
    if(mode==4) return snprintf(output,sizeof(output),"x%n",(int *)target);
    if(mode==5) return snprintf((char *)target+15,16,"bad");
    char text[]="ok";
    int result=snprintf((char *)target,16,"%s:%d:%.2f",text,7,1.25);
    return result==9 ? 1 : -1;
}
