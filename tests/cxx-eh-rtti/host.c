#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "sgx_urts.h"
#include "probe_u.h"
#include "../cxx-lifecycle/loaded_permissions.h"
int main(int argc, char **argv) {
  if (argc!=2 && argc!=3) return 1;
  sgx_enclave_id_t eid=0;
  sgx_status_t s=sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,0,0,&eid,0);
  if (s!=SGX_SUCCESS) { fprintf(stderr,"create: 0x%x\n",s); return 2; }
  permissions(argv[1]);
  if (argc==3) {
    int value=-999; s=exercise(eid,&value,atoi(argv[2]));
    printf("CONTROL_RETURN status=0x%x value=%d\n",s,value);
    sgx_destroy_enclave(eid);return 0;
  }
  const int expected[]={12,5,-9,21,1,31,32,47,18,1,19,13,1,1,1,12,14,37,19,53,1,19,55,38,1,39,63,1
#ifdef EH_LIBCXX
    ,1,1,1,1,1,1,1,1
#endif
  };
  const int actions=sizeof(expected)/sizeof(expected[0]);
  for (int a=0;a<actions;++a) {
    int value=-999; s=exercise(eid,&value,a);
    if (s!=SGX_SUCCESS || value!=expected[a]) {
      fprintf(stderr,"action %d: status=0x%x result=%d expected=%d\n",a,s,value,expected[a]); return 3;
    }
  }
  for (int i=0;i<8;++i) for (int a=0;a<actions;++a) {
    int value=-999; s=exercise(eid,&value,a);
    int want=a==2 ? 21 : expected[a];
    if (s!=SGX_SUCCESS || value!=want) {
      fprintf(stderr,"repeat %d action %d: status=0x%x result=%d expected=%d\n",i,a,s,value,want); return 4;
    }
  }
  if (sgx_destroy_enclave(eid)!=SGX_SUCCESS) return 5;
  printf("ENCBound SDK SIM EH/RTTI PASS: %d ECALLs\n",9*actions);
  return 0;
}
