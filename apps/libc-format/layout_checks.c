/* Trusted, test-only diagnostic. Returns only pass/fail; never exports a raw
 * address or capability and is not admitted as an application callable service. */
#include <stdint.h>
#include "encbound_runtime.h"
#include "encbound_platform.h"
int layout_checks(void) {
#ifdef ENCBOUND_PROTECTED
 /* Protected-global checks match the existing pre-stl/STL diagnostics. */
 unsigned compat=0,trusted=0,globals=0;
 for(size_t i=0;i<encbound_platform_region_count();++i) {
  encbound_region_t region;uintptr_t raw=0;
  if(!encbound_platform_region_at(i,&region))return -1;
  uintptr_t address=encbound_enclave_base()+region.start_offset;
  if(region.policy==ENCBOUND_REGION_TRUSTED) {
   if(encbound_check(address,1,ENCBOUND_ACCESS_READ,&raw)!=ENCBOUND_ERR_POLICY)return -2;
   if(encbound_check(address,1,ENCBOUND_ACCESS_WRITE,&raw)!=ENCBOUND_ERR_POLICY)return -3;
   ++trusted;
  } else if(region.policy==ENCBOUND_REGION_PROTECTED && region.domain==ENCBOUND_DOMAIN_GLOBAL) {
   if(encbound_check(address,1,ENCBOUND_ACCESS_READ,&raw)!=ENCBOUND_ERR_POLICY)return -8;
   if(encbound_check(address,1,ENCBOUND_ACCESS_WRITE,&raw)!=ENCBOUND_ERR_POLICY)return -9;
   ++globals;
  } else if(region.policy==ENCBOUND_REGION_COMPAT) {
   if(encbound_check(address,region.size,ENCBOUND_ACCESS_READ,&raw)!=ENCBOUND_OK || raw!=address)return -4;
   if(encbound_check(address,region.size+1,ENCBOUND_ACCESS_READ,&raw)==ENCBOUND_OK)return -5;
   if(encbound_check(address+region.size-1,2,ENCBOUND_ACCESS_WRITE,&raw)==ENCBOUND_OK)return -6;
   ++compat;
  }
 }
 if((globals ? compat<1 : compat<3) || trusted<5)return -7;
#endif
 return 0;
}
