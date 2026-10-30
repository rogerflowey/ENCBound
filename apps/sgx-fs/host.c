#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

static unsigned calls;
#define INT(want, expression) do { int value = -9999; sgx_status_t st=(expression); ++calls; if(st!=SGX_SUCCESS || value!=(want)) { fprintf(stderr,"line %d: status=%x result=%d expected=%d\n",__LINE__,st,value,(int)(want)); abort(); } } while(0)
#define STATUS(want, expression) do { sgx_status_t value=0xffffffff; sgx_status_t st=(expression); ++calls; if(st!=SGX_SUCCESS || value!=(want)) { fprintf(stderr,"line %d: status=%x result=%x expected=%x\n",__LINE__,st,value,(unsigned)(want)); abort(); } } while(0)
void ocall_print(const char *str) { fputs(str,stderr); }

/* F2 control: read one byte before a block boundary with a full-block length.
 * FileSystem::read_data clamps the copy to block->size(), not to the bytes
 * remaining after offset_in_block, so BASELINE returns adjacent enclave heap
 * content.  The checked memcpy adapter should reject the source extent. */
static int f2_control(sgx_enclave_id_t eid) {
  enum { F2_FILES=16, F2_BLOCK=4096 };
  char name[32];
  unsigned char *data=(unsigned char*)malloc(F2_BLOCK);
  unsigned char *out=(unsigned char*)calloc(1,F2_BLOCK);
  int value=-9999, leaks=0;
  assert(data && out);
  for(int i=0;i<F2_FILES;++i) {
    snprintf(name,sizeof name,"file%02d",i);
    INT(0,ramfs_create_file(eid,&value,name));
    memset(data,(unsigned char)('a'+i%26),F2_BLOCK);
    snprintf((char*)data,64,"MARKER-FILE-%02d-SECRET",i);
    INT(F2_BLOCK,ramfs_put(eid,&value,name,0,F2_BLOCK,(const char*)data));
  }
  for(int f=0;f<F2_FILES;++f) {
    snprintf(name,sizeof name,"file%02d",f);
    memset(out,0,F2_BLOCK);
    printf("F2_CALL victim=%s offset=%d size=%d\n",name,F2_BLOCK-1,F2_BLOCK);
    fflush(stdout);
    sgx_status_t st=ramfs_get(eid,&value,name,F2_BLOCK-1,F2_BLOCK,(char*)out);
    printf("F2_READ victim=%s status=%x result=%d\n",name,st,value);
    for(size_t i=1;i+12<F2_BLOCK;++i) {
      if(!memcmp(out+i,"MARKER-FILE-",12)) {
        printf("F2_LEAK victim=%s offset=%zu marker=%.24s\n",name,i,out+i);
        ++leaks;
      }
    }
  }
  printf("F2_DONE leaks=%d\n",leaks);
  free(data);free(out);
  return leaks ? 0 : 3;
}

int main(int argc, char **argv) {
  assert(argc==2 || argc==3);
  sgx_enclave_id_t eid=0;
  assert(sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,0,0,&eid,0)==SGX_SUCCESS);
  four_app_permissions(argv[1]);
  INT(0,init_filesystem(eid,&value));
  if(argc==3 && !strcmp(argv[2],"f2")) return f2_control(eid);
  INT(0,enclave_mkdir(eid,&value,"/docs"));
  INT(0,ramfs_create_file(eid,&value,"/docs/data"));
  if(argc==3) {
    /* Original readdir checks only i < length before copying a whole name. */
    INT(0,enclave_mkdir(eid,&value,"attack"));
    INT(0,ramfs_create_file(eid,&value,"attack/abcdefghijklmnopqrstuvwxyz0123456789"));
    char byte=0;
    int result=-9999;sgx_status_t st=enclave_readdir(eid,&result,"attack",&byte,1);
    printf("CONTROL_RETURN status=%x result=%d byte=%u\n",st,result,(unsigned char)byte);
    return 0;
  }
  INT(-EISDIR,enclave_mkdir(eid,&value,"docs"));
  INT(-ENOTDIR,enclave_mkdir(eid,&value,"missing/child"));
  INT(-EEXIST,ramfs_create_file(eid,&value,"docs/data"));
  INT(-EISDIR,ramfs_create_file(eid,&value,"docs"));
  INT(-ENOTDIR,ramfs_create_file(eid,&value,"absent/data"));
  INT(EEXIST,enclave_is_file(eid,&value,"///docs//data///"));
  INT(-EISDIR,enclave_is_file(eid,&value,"/docs"));
  INT(-ENOENT,enclave_is_file(eid,&value,"/missing"));
  unsigned char input[9000],output[9000];
  for(size_t i=0;i<sizeof input;++i)input[i]=(unsigned char)(i*37+11);
  INT(sizeof input,ramfs_put(eid,&value,"/docs/data",0,sizeof input,(const char*)input));
  INT(sizeof input,ramfs_get_size(eid,&value,"docs/data"));
  memset(output,0,sizeof output);
  INT(sizeof output,ramfs_get(eid,&value,"docs/data",0,sizeof output,(char*)output));
  assert(!memcmp(input,output,sizeof input));
  INT(37,ramfs_get(eid,&value,"docs/data",4096,37,(char*)output));assert(!memcmp(input+4096,output,37));
  unsigned char patch[19];memset(patch,0x79,sizeof patch);
  INT(sizeof patch,ramfs_put(eid,&value,"docs/data",4103,sizeof patch,(char*)patch));
  memcpy(input+4103,patch,sizeof patch);
  /* The original write resizes the existing block to offset+length. Use a
     fresh file for persistence; this behavior is recorded, not corrected. */
  INT(9000,ramfs_get_size(eid,&value,"docs/data"));
  INT(0,ramfs_create_file(eid,&value,"docs/persist"));
  INT(6000,ramfs_put(eid,&value,"docs/persist",0,6000,(char*)input));
  INT(0,ramfs_get(eid,&value,"docs/persist",8192,31,(char*)output));
  INT(-ENOENT,ramfs_get(eid,&value,"missing",0,31,(char*)output));
  INT(-ENOENT,ramfs_put(eid,&value,"missing",0,31,(char*)input));
  INT(-ENOENT,ramfs_trunkate(eid,&value,"missing",0));
  /* Zero truncation has a definite oracle despite upstream rounding bugs. */
  INT(0,ramfs_trunkate(eid,&value,"docs/data",0));
  INT(0,ramfs_get_size(eid,&value,"docs/data"));
  INT(-ENOTDIR,ramfs_delete_file(eid,&value,"docs/data"));
  INT(EEXIST,enclave_is_file(eid,&value,"docs/data"));
  char entries[256];memset(entries,0,sizeof entries);
  INT(2,enclave_readdir(eid,&value,"docs",entries,sizeof entries));
  assert(!memcmp(entries,"data\x1c" "persist\x1c",13));
  INT(1,ramfs_get_number_of_entries(eid,&value));
  for(unsigned i=0;i<20;++i) {
    INT(-ENOENT,enclave_readdir(eid,&value,"absent",entries,sizeof entries));
    INT(2,enclave_readdir(eid,&value,"docs",entries,sizeof entries));
  }
  size_t sealed_size=sizeof(sgx_sealed_data_t)+6000;
  sgx_sealed_data_t *sealed=calloc(1,sealed_size);assert(sealed);
  STATUS(SGX_SUCCESS,seal(eid,&value,input,6000,sealed,sealed_size));
  STATUS(SGX_SUCCESS,unseal(eid,&value,sealed,sealed_size,output,6000));assert(!memcmp(input,output,6000));
  STATUS(SGX_ERROR_INVALID_PARAMETER,unseal(eid,&value,sealed,sealed_size,output,1));
  ((unsigned char*)sealed)[sealed_size-1]^=1;
  STATUS(SGX_ERROR_MAC_MISMATCH,unseal(eid,&value,sealed,sealed_size,output,6000));
  ((unsigned char*)sealed)[sealed_size-1]^=1;
  STATUS(SGX_SUCCESS,ramfs_encrypt(eid,&value,"unused",input,6000,sealed,sealed_size));
  STATUS(SGX_SUCCESS,ramfs_decrypt(eid,&value,"unused",sealed,sealed_size,output,6000));assert(!memcmp(input,output,6000));
  INT(-ENOENT,sgxfs_dump(eid,&value,"missing",sealed,sealed_size));
  INT(SGX_SUCCESS,sgxfs_dump(eid,&value,"docs/persist",sealed,sealed_size));
  INT(0,ramfs_create_file(eid,&value,"docs/restored"));
  INT(SGX_SUCCESS,sgxfs_restore(eid,&value,"docs/restored",sealed,sealed_size));
  INT(6000,ramfs_get(eid,&value,"docs/restored",0,6000,(char*)output));assert(!memcmp(input,output,6000));
  INT(0,sgxfs_restore(eid,&value,"docs/not-created",sealed,sealed_size));
  INT(-ENOENT,enclave_is_file(eid,&value,"docs/not-created"));
  INT(-1,destroy_filesystem(eid,&value));
  free(sealed);assert(sgx_destroy_enclave(eid)==SGX_SUCCESS);
  printf("SGX-FS SDK SIM PASS: %u ECALLs; original 18-entry interface\n",calls);
  return 0;
}
