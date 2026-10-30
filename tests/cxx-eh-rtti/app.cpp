#include "objects.h"
#include <new>
#include <cstdint>
#ifdef EH_LIBCXX
#include <vector>
#include <string>
#include <optional>
#include <any>
#include <variant>
#include <functional>
#include <stdexcept>
#include <memory>
#endif
struct VGuard { static int active; VGuard() { ++active; } ~VGuard() { --active; } };
int VGuard::active;
struct ArrayItem {
  static int attempts,live;
  ArrayItem() { if (++attempts==3) throw 14; ++live; }
  ~ArrayItem() { --live; }
};
int ArrayItem::attempts,ArrayItem::live;
struct CopyFail { CopyFail() {} CopyFail(const CopyFail &) { throw 37; } };
static Startup startup;
struct Blob { char data[32]; };
#ifdef EH_LIBCXX
struct SharedItem {
  int *destroyed; int value;
  SharedItem(int *count,int n):destroyed(count),value(n) {}
  ~SharedItem() { ++*destroyed; }
};
struct StatefulDelete {
  int *deleted;
  void operator()(SharedItem *p) const { ++*deleted; delete p; }
};
#endif
struct BadCleanup {
  char data[32];
  __attribute__((noinline)) ~BadCleanup() { *reinterpret_cast<volatile unsigned short *>(data+31)=0xbeef; }
};
__attribute__((noinline)) static int vla_fail(int n) { VGuard items[n]; throw 12; }
__attribute__((noinline)) static void no_throw() noexcept { throw_value(17); }
struct Guard { int *p; explicit Guard(int *v): p(v) { ++*p; } ~Guard() { --*p; } };
struct Local { int value; explicit Local(int x) { if (!x) throw 9; value=x; } };
static int first_use(int x) { static Local item(x); return item.value; }
extern "C" __attribute__((noinline)) int private_read(uintptr_t bits) { return *reinterpret_cast<volatile unsigned char *>(bits); }
extern "C" __attribute__((noinline)) int private_cast(uintptr_t bits) {
  return dynamic_cast<VDiamond *>(reinterpret_cast<VRoot *>(bits))!=nullptr;
}
extern "C" int exercise(int action) {
  if (action == 0) { try { throw_value(11); } catch (int e) { return e+1; } }
  if (action == 1) {
    int count=0;
    try { Guard g(&count); throw_value(5); } catch (int e) { return count+e; }
  }
  if (action == 2 || action == 3) {
    try { return first_use(action == 2 ? 0 : 21); } catch (int e) { return -e; }
  }
  if (action == 4) {
    Derived d; Base *p=&d;
    return dynamic_cast<Derived *>(p)==&d && !dynamic_cast<Other *>(p)
      && dynamic_cast<void *>(p)==&d && &typeid(*p)==derived_type()
      && typeid(*p)==typeid(Derived) && typeid(Derived).name()[0];
  }
  if (action == 5) {
    Base b;
    try { (void)dynamic_cast<Derived &>(b); } catch (const std::bad_cast &) { return 31; }
  }
  if (action == 6) {
    Base *p=nullptr;
    try { (void)typeid(*p); } catch (const std::bad_typeid &) { return 32; }
  }
  if (action == 7) {
    try { try { throw_value(7); } catch (int) { throw; } }
    catch (int e) { return e+40; }
  }
  if (action == 8) {
    int state=0, result=0;
    try { throw_payload(&state); } catch (Payload &p) {
      if (p.state!=&state || state!=0) return -81;
      result=p.value;
    }
    return result+state;
  }
  if (action==9) {
    Multi m; Left *l=&m; Right *r=&m;
    return dynamic_cast<Right *>(l)==r && dynamic_cast<Multi *>(r)==&m
      && dynamic_cast<void *>(r)==&m && typeid(*r)==typeid(Multi);
  }
  if (action==10) { try { throw_multi(); } catch (Right &r) { return r.r; } }
  if (action==11) {
    Multi m;
    try { throw_pointer(&m); } catch (const Left *p) { return p==static_cast<Left *>(&m) ? p->l : -11; }
  }
  if (action==12) { try { throw_pointer(nullptr); } catch (Left *p) { return p==nullptr; } }
  if (action==13) {
    try { (void)::operator new(static_cast<size_t>(-1)); }
    catch (const std::bad_alloc &e) { return e.what()[0]!=0; }
  }
  if (action==14) { return ::operator new(static_cast<size_t>(-1),std::nothrow)==nullptr; }
  if (action==15) { try { vla_fail(9); } catch (int e) { return e+VGuard::active; } }
  if (action==16) {
    ArrayItem::attempts=0;
    try { auto *a=new ArrayItem[5]; delete[] a; } catch (int e) { return e+ArrayItem::live; }
  }
  if (action==17) { CopyFail p; try { throw p; } catch (int e) { return e; } }
  if (action==18) {
    int state=0,value=0;
    try { throw_payload(&state); } catch (Payload p) { value=p.value; }
    return value+state;
  }
  if (action==19) {
    try { try { throw_value(3); } catch(int) { try { throw; } catch(int e) { if(e!=3)return -1; } throw; } }
    catch(int e) { return e+50; }
  }
  if (action==20) { return startup.value==7 && typeid(int).name()[0]=='i' && typeid(int)==typeid(int) && typeid(int).hash_code()==typeid(int).hash_code(); }
  if (action==21) { Multi m;try { throw_multi_pointer(&m); } catch(const Right *p) { return p==static_cast<Right *>(&m) ? p->r : -21; } }
  if (action==22) { try { aggregate_throw(Large{{1,2,3,4,55}}); } catch(long v) { return static_cast<int>(v); } }
  if (action==23) { try { variadic_throw(5,33); } catch(int v) { return v; } }
  if (action==24) { try { throw static_cast<Right *>(nullptr); } catch(const Right *p) { return p==nullptr; } }
  if (action==25) { try { throw 19.5; } catch(double v) { return static_cast<int>(2*v); } }
  if (action==26) { enum class E { good=63 };try { throw E::good; } catch(E v) { return static_cast<int>(v); } }
  if (action==27) {
    // Cross-unit source pointers prevent the frontend from resolving casts.
    // A shared virtual root has a real object-dependent offset in each vtable.
    VDiamond d; VRoot *root=virtual_root(&d); VLeft *left=&d; VRight *right=&d;
    if (dynamic_cast<VDiamond *>(root)!=&d || dynamic_cast<VRight *>(left)!=right ||
        dynamic_cast<VLeft *>(root)!=left || dynamic_cast<void *>(root)!=&d ||
        dynamic_cast<Other *>(root) || typeid(*root)!=typeid(VDiamond)) return -271;
    try { throw_virtual(); } catch (VRoot &v) { if (v.n!=41) return -272; }
    try { throw_virtual_pointer(&d); } catch (const VRoot *v) { if (v!=root || v->n!=41) return -273; }
    // The owner selected SDK semantics. Its traversal follows nonpublic bases
    // and chooses the first repeated base. Assert the actual SDK comparison,
    // rather than substituting the host C++ runtime's different answers.
    SdkPrivate p; SdkProtected q; SdkRepeated r;
    if (dynamic_cast<SdkRoot *>(sdk_private_anchor(&p))!=p.root() ||
        dynamic_cast<SdkRoot *>(sdk_protected_anchor(&q))!=q.root() ||
        dynamic_cast<SdkRoot *>(sdk_repeated_anchor(&r))!=static_cast<SdkBranchA *>(&r)) return -274;
    try { throw_sdk_private(); } catch(SdkRoot &v) { if(v.n!=61)return -275; }
    try { throw_sdk_repeated(); } catch(SdkRoot &v) { if(v.n!=61)return -276; }
    return function_type()==&typeid(int(double)) && typeid(int(double))!=typeid(int(int)) &&
           typeid(int(double)).name()[0] && typeid(int(*)(double))!=typeid(int(*)(int));
  }
  // Regression for the local SDK-source null-upcast correction. The unmodified
  // BASELINE SDK dereferences null here; keep its diagnostic separate from the
  // matched normal-behavior matrix.
  if (action==130) { try { throw_virtual_pointer(nullptr); } catch (const VRoot *v) { return v==nullptr; } }
#ifdef EH_LIBCXX
  if (action==28) { std::vector<int> v{1,2};try { (void)v.at(3); } catch(const std::out_of_range &e) { return e.what()[0]!=0; } }
  if (action==29) { std::string s(80,'x');try { (void)s.at(99); } catch(const std::out_of_range &e) { return e.what()[0]!=0; } }
  if (action==30) { std::optional<int> p;try { (void)p.value(); } catch(const std::bad_optional_access &e) { return e.what()[0]!=0; } }
  if (action==31) { std::any p=7;try { (void)std::any_cast<double>(p); } catch(const std::bad_any_cast &e) { return e.what()[0]!=0; } }
  if (action==32) { std::variant<int,double> p=7;try { (void)std::get<double>(p); } catch(const std::bad_variant_access &e) { return e.what()[0]!=0; } }
  if (action==33) { std::function<int()> p;try { (void)p(); } catch(const std::bad_function_call &e) { return e.what()[0]!=0; } }
  if (action==34) { try { throw std::overflow_error("payload-owned error string beyond SSO capacity"); } catch(const std::exception &e) { return e.what()[0]=='p'; } }
  if (action==35) {
    int destroyed=0,deleted=0;
    std::weak_ptr<SharedItem> weak;
    {
      auto owner=std::make_shared<SharedItem>(&destroyed,71);
      weak=owner;
      auto copy=owner;
      auto locked=weak.lock();
      if(owner.use_count()!=3 || locked.get()!=owner.get() || locked->value!=71)return -351;
      copy.reset(); locked.reset();
      auto custom=std::shared_ptr<SharedItem>(new SharedItem(&destroyed,73),StatefulDelete{&deleted});
      const auto *deleter=std::get_deleter<StatefulDelete>(custom);
      if(!deleter || deleter->deleted!=&deleted || std::get_deleter<int>(custom))return -352;
      custom.reset();
      if(destroyed!=1 || deleted!=1 || weak.expired())return -353;
    }
    if(destroyed!=2 || !weak.expired() || weak.lock())return -354;
    try { std::shared_ptr<SharedItem> absent(weak); return -355; }
    catch(const std::bad_weak_ptr &e) { if(!e.what()[0])return -356; }
    weak.reset();
    return destroyed==2 && deleted==1;
  }
#endif
  if (action>=100 && action<=102) {
    try { throw Blob{}; } catch (Blob &b) {
      if (action==100) *reinterpret_cast<volatile unsigned short *>(b.data+31)=0xbeef;
      uintptr_t p=reinterpret_cast<uintptr_t>(&b);
      if (action==101) p^=1ull<<32;
      if (action==102) p=(reinterpret_cast<uintptr_t>(typeid(Blob).name()) & ~((1ull<<30)-1)) + static_cast<uint32_t>(p);
      return *reinterpret_cast<volatile unsigned char *>(p);
    }
  }
  if (action==103) { try { no_throw(); } catch (...) { return -103; } }
  if (action==104) throw_value(104); // must terminate at the emitted ECALL wrapper
  if (action==105) { try { throw BadCleanup{}; } catch (...) {} }
  // The debugger supplies private addresses at private_read's argument entry.
  // No production service returns headers, TLS or unwind state to application code.
  if (action==106) { try { throw Blob{}; } catch(Blob &b) { return private_read(reinterpret_cast<uintptr_t>(&b)); } }
  if (action==120 || action==121) {
    VDiamond d;
    uintptr_t bits=reinterpret_cast<uintptr_t>(virtual_root(&d));
    if (action==120) {
      size_t slot=1; while (slot<sizeof(d)) slot*=2;
      bits=reinterpret_cast<uintptr_t>(&d)+slot-1;
    } else bits^=1ull<<32;
    return private_cast(bits);
  }
  return -100;
}
