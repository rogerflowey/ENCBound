#include <typeinfo>
struct Base { virtual int value() const; virtual ~Base(); };
struct Derived : Base { int value() const override; };
struct Other : Base { int value() const override; };
void throw_value(int);
const std::type_info *derived_type();
struct Payload { int *state; int value; ~Payload(); };
struct Left { int l=13; virtual ~Left(); };
struct Right { int r=19; virtual ~Right(); };
struct Multi : Left, Right { int x=23; };
void throw_multi();
void throw_pointer(Left *);
void throw_multi_pointer(Multi *);
struct Large { long a[5]; };
void aggregate_throw(Large);
void variadic_throw(int,...);
struct Startup { int value; Startup(); ~Startup(); };
void throw_payload(int *);
struct VRoot { int n=41; virtual ~VRoot(); };
struct VLeft : virtual VRoot { int l=43; virtual ~VLeft(); };
struct VRight : virtual VRoot { int r=47; virtual ~VRight(); };
struct VDiamond : VLeft, VRight { int d=53; };
VRoot *virtual_root(VDiamond *);
void throw_virtual();
void throw_virtual_pointer(VDiamond *);
const std::type_info *function_type();
// These graph cases intentionally compare against the pinned SDK's traversal,
// including its first-match and nonpublic-base behavior.
struct SdkRoot { int n=61; virtual ~SdkRoot(); };
struct SdkPrivate : private SdkRoot, Left { SdkRoot *root(); };
struct SdkProtected : protected SdkRoot, Left { SdkRoot *root(); };
struct SdkBranchA : SdkRoot {};
struct SdkBranchB : SdkRoot {};
struct SdkRepeated : SdkBranchA, SdkBranchB, Left {};
Left *sdk_private_anchor(SdkPrivate *);
Left *sdk_protected_anchor(SdkProtected *);
Left *sdk_repeated_anchor(SdkRepeated *);
void throw_sdk_private();
void throw_sdk_repeated();
