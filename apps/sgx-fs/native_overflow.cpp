#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "Enclave_t.h"

int main(int argc,char **argv) {
  assert(argc==2);
  assert(init_filesystem()==0);
  assert(enclave_mkdir("attack")==0);
  assert(ramfs_create_file("attack/abcdefghijklmnopqrstuvwxyz0123456789")==0);
  size_t size=strcmp(argv[1],"short")==0 ? 1 : 64;
  char *data=static_cast<char*>(malloc(size));assert(data);memset(data,0,size);
  int result=enclave_readdir("attack",data,size);
  assert(result==1);
  assert(!memcmp(data,"abcdefghijklmnopqrstuvwxyz0123456789\x1c",37));
  free(data);assert(destroy_filesystem()==-1);
  puts("SGX-FS native readdir full-buffer PASS");
}
