#include "objects.h"
#include <cstdarg>
#include <cstdlib>
int Base::value() const { return 1; }
Base::~Base() = default;
int Derived::value() const { return 2; }
int Other::value() const { return 3; }
__attribute__((noinline)) void throw_value(int x) { throw x; }
const std::type_info *derived_type() { return &typeid(Derived); }
Payload::~Payload() { ++*state; }
__attribute__((noinline)) void throw_payload(int *p) { throw Payload{p, 17}; }
Left::~Left() = default;
Right::~Right() = default;
__attribute__((noinline)) void throw_multi() { throw Multi{}; }
__attribute__((noinline)) void throw_pointer(Left *p) { throw p; }
__attribute__((noinline)) void throw_multi_pointer(Multi *p) { throw p; }
__attribute__((noinline)) void aggregate_throw(Large p) { throw p.a[4]; }
__attribute__((noinline)) void variadic_throw(int n,...) {
  va_list v;va_start(v,n);int value=va_arg(v,int);va_end(v);throw value+n;
}
Startup::Startup() { try { throw_value(7); } catch(int v) { value=v; } }
Startup::~Startup() { if(value!=7) abort(); }
VRoot::~VRoot() = default;
VLeft::~VLeft() = default;
VRight::~VRight() = default;
__attribute__((noinline)) VRoot *virtual_root(VDiamond *p) { return p; }
__attribute__((noinline)) void throw_virtual() { throw VDiamond{}; }
__attribute__((noinline)) void throw_virtual_pointer(VDiamond *p) { throw p; }
const std::type_info *function_type() { return &typeid(int(double)); }
SdkRoot::~SdkRoot() = default;
SdkRoot *SdkPrivate::root() { return this; }
SdkRoot *SdkProtected::root() { return this; }
__attribute__((noinline)) Left *sdk_private_anchor(SdkPrivate *p) { return p; }
__attribute__((noinline)) Left *sdk_protected_anchor(SdkProtected *p) { return p; }
__attribute__((noinline)) Left *sdk_repeated_anchor(SdkRepeated *p) { return p; }
__attribute__((noinline)) void throw_sdk_private() { throw SdkPrivate{}; }
__attribute__((noinline)) void throw_sdk_repeated() { throw SdkRepeated{}; }
