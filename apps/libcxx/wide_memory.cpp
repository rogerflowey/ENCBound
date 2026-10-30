// Application implementations of demanded wide-character services. These are
// instrumented, never raw SDK adapters. wchar_t is 32 bits in the pinned ABI.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
static_assert(sizeof(wchar_t)==4,"wide ABI");
extern "C" {
void *memchr(const void *p,int c,size_t n) {
 const unsigned char *s=(const unsigned char*)p;
 for(size_t i=0;i<n;++i)if(s[i]==(unsigned char)c)return (void*)(s+i);
 return nullptr;
}
wchar_t *wmemcpy(wchar_t *d,const wchar_t *s,size_t n) {
 for(size_t i=0;i<n;++i)d[i]=s[i];return d;
}
wchar_t *wmemmove(wchar_t *d,const wchar_t *s,size_t n) {
 // Encoded pointer ordering across allocations is not raw address ordering.
 // Same-object capabilities share radix/tag bits, so subtraction gives the
 // byte displacement. Either copy direction is valid for distinct allocations.
 uintptr_t dst=(uintptr_t)d,src=(uintptr_t)s;
 if(dst>src && (dst-src)/sizeof(wchar_t)<n) {
  while(n){--n;d[n]=s[n];}
 } else for(size_t i=0;i<n;++i)d[i]=s[i];
 return d;
}
wchar_t *wmemset(wchar_t *d,wchar_t c,size_t n) { for(size_t i=0;i<n;++i)d[i]=c;return d; }
wchar_t *wmemchr(const wchar_t *s,wchar_t c,size_t n) { for(size_t i=0;i<n;++i)if(s[i]==c)return (wchar_t*)(s+i);return nullptr; }
int wmemcmp(const wchar_t *a,const wchar_t *b,size_t n) { for(size_t i=0;i<n;++i)if(a[i]!=b[i])return a[i]<b[i]?-1:1;return 0; }
size_t wcslen(const wchar_t *s) { size_t n=0;while(s[n])++n;return n; }
}
