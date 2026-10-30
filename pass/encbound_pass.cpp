// ENCBound restart - step 4 LLVM 21 instrumentation pass.
//
// Loaded as an LLVM pass plugin and run only on admitted application IR, never
// on trusted runtime or SDK IR. It:
//   * redirects application allocation calls to the runtime allocator;
//   * rewrites fixed-size and opt-in dynamic stack objects to aligned, cleared slots minted by the
//     runtime and uses their stack capability;
//   * routes every admitted load/store/memory intrinsic through
//     `encbound_require(bits, width, kind) -> raw`;
//   * rejects unsupported constructs, unadmitted atomic/indirect calls, inline asm, and
//     calls to external symbols not admitted by the build inventory.
//
// Access kinds must match include/encbound_common.h.
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/MD5.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/NoFolder.h"
#include <cstdlib>

using namespace llvm;

namespace encbound_variadics { void expand(Module &M); }

namespace {

constexpr unsigned kAccessRead = 1;
constexpr unsigned kAccessWrite = 2;
constexpr unsigned kAccessReadWrite = 3;
cl::opt<bool> AtomicsOption("encbound-atomics", cl::init(false), cl::Hidden);
cl::opt<bool> ProtectedGlobalsOption("encbound-protected-globals", cl::init(false), cl::Hidden);
cl::opt<bool> CxxLifecycleOption("encbound-cxx-lifecycle", cl::init(false), cl::Hidden);
cl::opt<bool> VLAOption("encbound-vla", cl::init(false), cl::Hidden);
cl::opt<bool> CxxEHOption("encbound-cxx-eh", cl::init(false), cl::Hidden);
cl::opt<std::string> CxxEHEntries("encbound-cxx-eh-entries",cl::init(""),cl::Hidden);
void markLifecycle(Module &M);
void prepareCxxEH(Module &M, SmallPtrSetImpl<Function *> &Routed);
void verifyCxxEH(Function &F, bool Output);
void normalizeCxxEHTokens(Function &F);
void createCxxEHBoundaries(Module &M, bool Baseline);

// Initially admit naturally aligned scalar integer atomics, 8 through 64 bits.
// Preserve the operation, ordering, volatility and synchronization scope.
bool admittedAtomic(const Instruction &I) {
    if (!AtomicsOption) return false;
    if (isa<FenceInst>(I)) return true;
    Type *T = nullptr; unsigned Alignment = 0;
    if (auto *L = dyn_cast<LoadInst>(&I)) { T=L->getType(); Alignment=L->getAlign().value(); }
    else if (auto *S = dyn_cast<StoreInst>(&I)) { T=S->getValueOperand()->getType(); Alignment=S->getAlign().value(); }
    else if (auto *R = dyn_cast<AtomicRMWInst>(&I)) { T=R->getValOperand()->getType(); Alignment=R->getAlign().value(); }
    else if (auto *C = dyn_cast<AtomicCmpXchgInst>(&I)) { T=C->getCompareOperand()->getType(); Alignment=C->getAlign().value(); }
    if (!T || !T->isIntegerTy()) return false;
    unsigned Bits=T->getIntegerBitWidth();
    return (Bits==8 || Bits==16 || Bits==32 || Bits==64) && Alignment>=Bits/8;
}

cl::opt<std::string> CheckReuseOption("encbound-check-reuse",
    cl::desc("Compiler-private guarded span reuse: off, block, loop"),
    cl::init("off"), cl::Hidden);

bool namedCall(const Instruction &I, StringRef Name) {
    auto *C = dyn_cast<CallInst>(&I);
    return C && C->getCalledFunction() && C->getCalledFunction()->getName() == Name;
}

bool spanBarrier(const Instruction &I) {
    if (isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) || isa<FenceInst>(I)) return true;
    if (auto *L = dyn_cast<LoadInst>(&I)) return L->isVolatile() || L->isAtomic();
    if (auto *S = dyn_cast<StoreInst>(&I)) return S->isVolatile() || S->isAtomic();
    if (!isa<CallBase>(I)) return false;
    return !(namedCall(I,"encbound_require") || namedCall(I,"encbound_span_require") ||
             namedCall(I,"encbound_span_prepare"));
}

// Find an SSA pointer origin through GEP and full-width address arithmetic.
// Loads/PHIs/selects are new origins; never inherit a token from a
// memory location. Guarded span_require validates every resulting capability.
Value *spanOrigin(Value *V, unsigned Depth = 0) {
    if (Depth > 32) return nullptr;
    if (auto *G = dyn_cast<GetElementPtrInst>(V))
        return spanOrigin(G->getPointerOperand(), Depth + 1);
    if (auto *C = dyn_cast<CastInst>(V)) {
        if (isa<PtrToIntInst>(C) || isa<IntToPtrInst>(C))
            return spanOrigin(C->getOperand(0), Depth + 1);
    }
    if (auto *B = dyn_cast<BinaryOperator>(V)) {
        if (B->getOpcode() == Instruction::Add) {
            Value *A = spanOrigin(B->getOperand(0), Depth+1);
            Value *C = spanOrigin(B->getOperand(1), Depth+1);
            return A && !C ? A : (!A ? C : nullptr);
        }
    }
    return V->getType()->isPointerTy() ? V : nullptr;
}

// Bounded local proofs deliberately do not use inbounds, alias metadata or
// general value-range/undefined-behavior assumptions.
cl::opt<bool> LocalProofsOption("encbound-local-proofs", cl::init(false),
    cl::desc("Eliminate statically covered local scalar access checks"), cl::Hidden);

struct ConstantAddress {
    Value *Base;
    uint64_t Offset;
};
ConstantAddress constantAddress(Value *V, unsigned Depth = 0) {
    if (Depth == 32) return {V,0};
    if (auto *G = dyn_cast<GetElementPtrInst>(V)) {
        APInt Offset(64, 0);
        if (G->accumulateConstantOffset(G->getModule()->getDataLayout(), Offset)) {
            auto A = constantAddress(G->getPointerOperand(), Depth + 1);
            A.Offset += Offset.getZExtValue();
            return A;
        }
    }
    if (auto *P=dyn_cast<PtrToIntInst>(V)) {
        if (P->getType()->isIntegerTy(64)) return constantAddress(P->getOperand(0),Depth+1);
    }
    if (auto *P=dyn_cast<IntToPtrInst>(V)) {
        if (P->getOperand(0)->getType()->isIntegerTy(64)) return constantAddress(P->getOperand(0),Depth+1);
    }
    if (auto *B=dyn_cast<BinaryOperator>(V)) {
        if (B->getOpcode()==Instruction::Add && B->getType()->isIntegerTy(64)) {
            for (unsigned I=0; I<2; ++I) if (auto *K=dyn_cast<ConstantInt>(B->getOperand(I))) {
                auto A=constantAddress(B->getOperand(1-I),Depth+1);
                A.Offset+=K->getZExtValue(); // representation arithmetic modulo 2^64
                return A;
            }
        }
    }
    return {V,0};
}
bool clearProofScope(Instruction *From, Instruction *To) {
    if (From==To || From->getParent()!=To->getParent() || !From->comesBefore(To)) return false;
    for (auto I=std::next(From->getIterator()); &*I!=To; ++I)
        if (spanBarrier(*I)) return false;
    return !spanBarrier(*To);
}
bool scalarProofAccess(Instruction *I, Value *Address, uint64_t &Width, unsigned &Kind) {
    auto &DL=I->getModule()->getDataLayout();
    if (auto *L=dyn_cast<LoadInst>(I)) {
        if (L->isVolatile() || L->isAtomic() || L->getPointerOperand()!=Address) return false;
        Width=DL.getTypeStoreSize(L->getType()); Kind=kAccessRead; return Width!=0;
    }
    if (auto *S=dyn_cast<StoreInst>(I)) {
        if (S->isVolatile() || S->isAtomic() || S->getPointerOperand()!=Address ||
            S->getValueOperand()==Address) return false;
        Width=DL.getTypeStoreSize(S->getValueOperand()->getType()); Kind=kAccessWrite; return Width!=0;
    }
    return false;
}
bool mintedLocal(CallInst *Mint, AllocaInst *&Slot, uint64_t &Size) {
    if (!Mint || !namedCall(*Mint,"encbound_stack_mint") || Mint->arg_size()!=2 ||
        Mint->getCallingConv()!=CallingConv::C || Mint->hasOperandBundles()) return false;
    auto &C=Mint->getContext(); auto *I64=Type::getInt64Ty(C);
    if (Mint->getFunctionType()!=FunctionType::get(I64,{PointerType::get(C,0),I64},false)) return false;
    Slot=dyn_cast<AllocaInst>(Mint->getArgOperand(0));
    auto *K=dyn_cast<ConstantInt>(Mint->getArgOperand(1));
    auto *N=Slot ? dyn_cast<ConstantInt>(Slot->getArraySize()) : nullptr;
    if (!Slot || !Slot->isStaticAlloca() || !Slot->getAllocatedType()->isIntegerTy(8) ||
        Slot->getAddressSpace()!=0 || !K || !N || N->getType()!=K->getType() || N->getValue()!=K->getValue()) return false;
    Size=K->getZExtValue();
    return Size>=16 && Size<=(1ull<<30) && isPowerOf2_64(Size) && Slot->getAlign().value()>=Size &&
        Slot->getParent()==Mint->getParent() && Slot->comesBefore(Mint);
}
// A raw proof tree is ONLY bounded constant additions and one-use decodes into
// scalar addresses. Every leaf is checked, including otherwise orphan escapes.
bool confinedProofTree(Value *V, uint64_t Offset, uint64_t Bound, unsigned Kind,
                       Instruction *Start, unsigned Depth=0) {
    if (Depth>16 || V->use_empty()) return false;
    for (User *U : V->users()) {
        if (auto *Add=dyn_cast<BinaryOperator>(U)) {
            if (Add->getOpcode()!=Instruction::Add || Add->getOperand(0)!=V ||
                Add->hasNoUnsignedWrap() || Add->hasNoSignedWrap()) return false;
            auto *K=dyn_cast<ConstantInt>(Add->getOperand(1));
            if (!K || !K->getType()->isIntegerTy(64) || Offset>Bound || K->getZExtValue()>Bound-Offset ||
                !confinedProofTree(Add,Offset+K->getZExtValue(),Bound,Kind,Start,Depth+1)) return false;
            continue;
        }
        auto *IP=dyn_cast<IntToPtrInst>(U);
        if (!IP || !IP->hasOneUse() || IP->getAddressSpace()!=0) return false;
        auto *Access=dyn_cast<Instruction>(*IP->user_begin());
        uint64_t Width=0; unsigned AccessKind=0;
        if (!Access || !scalarProofAccess(Access,IP,Width,AccessKind) ||
            (Kind && AccessKind!=Kind) || Offset>Bound || Width>Bound-Offset ||
            !clearProofScope(Start,Access)) return false;
    }
    return true;
}
bool checkedProofRoot(CallInst *C) {
    if (!C || !(namedCall(*C,"encbound_require") || namedCall(*C,"encbound_span_require"))) return false;
    auto &Ctx=C->getContext(); auto *I64=Type::getInt64Ty(Ctx); auto *I32=Type::getInt32Ty(Ctx);
    auto *Type=namedCall(*C,"encbound_require") ? FunctionType::get(I64,{I64,I64,I32},false) :
        FunctionType::get(I64,{I64,I64,I32,I64,I64},false);
    if (C->getFunctionType()!=Type || C->getCallingConv()!=CallingConv::C || C->hasOperandBundles()) return false;
    auto *W=dyn_cast<ConstantInt>(C->getArgOperand(1)); auto *K=dyn_cast<ConstantInt>(C->getArgOperand(2));
    return W && K && W->getZExtValue() && (K->getZExtValue()==1 || K->getZExtValue()==2) &&
        confinedProofTree(C,0,W->getZExtValue(),K->getZExtValue(),C);
}
bool localProofRoot(PtrToIntInst *Raw) {
    auto *Slot=dyn_cast<AllocaInst>(Raw->getPointerOperand());
    if (!Slot || !Raw->getType()->isIntegerTy(64)) return false;
    CallInst *Mint=nullptr;
    for (User *U : Slot->users()) {
        if (auto *C=dyn_cast<CallInst>(U)) {
            AllocaInst *A=nullptr; uint64_t Size=0;
            if (Mint || !mintedLocal(C,A,Size) || A!=Slot) return false;
            Mint=C;
        } else if (!isa<PtrToIntInst>(U)) return false;
    }
    AllocaInst *A=nullptr; uint64_t Size=0;
    if (!mintedLocal(Mint,A,Size)) return false;
    for (User *U : Slot->users()) if (auto *R=dyn_cast<PtrToIntInst>(U))
        if (!R->getType()->isIntegerTy(64) || !confinedProofTree(R,0,Size,0,Mint)) return false;
    return true;
}
bool provenAddress(Value *Address, Instruction *Access) {
    auto *IP=dyn_cast<IntToPtrInst>(Address);
    if (!IP || !IP->hasOneUse() || *IP->user_begin()!=Access) return false;
    Value *Root=IP->getOperand(0);
    for (unsigned Depth=0; Depth<=16; ++Depth) {
        if (auto *C=dyn_cast<CallInst>(Root)) return checkedProofRoot(C);
        if (auto *R=dyn_cast<PtrToIntInst>(Root)) return localProofRoot(R);
        auto *Add=dyn_cast<BinaryOperator>(Root);
        if (!Add || Add->getOpcode()!=Instruction::Add) return false;
        Root=Add->getOperand(0);
    }
    return false;
}

// Optional inventory of additional admitted external symbols (one per line,
// '#' comments). Cross-translation-unit application/dependency symbols listed
// here pass call admission; see docs/legacy/steps/04-compiler.md. Without the file, only
// the trusted runtime helpers below are admitted externals.
cl::opt<std::string> AdmittedSymbolsFile(
    "encbound-admitted-file",
    cl::desc("File listing admitted external application/dependency symbols"),
    cl::value_desc("path"), cl::Hidden);

// Protection profile recorded in each instrumented object so the build
// inventory can verify profile identity per object (static review P1 #2/#1).
cl::opt<std::string> ProfileOption(
    "encbound-profile",
    cl::desc("Protection profile recorded in the object audit marker"),
    cl::value_desc("name"), cl::Hidden);

// Emit `__encbound_instrumented` into section `.encbound.audit` holding the
// profile string. Present only in objects that passed through this pass.
bool addInstrumentedMarker(Module &M) {
    if (M.getNamedValue("__encbound_instrumented") != nullptr) {
        return false;
    }
    LLVMContext &Ctx = M.getContext();
    StringRef profile =
        ProfileOption.empty() ? StringRef("unknown") : StringRef(ProfileOption);
    Constant *init = ConstantDataArray::getString(Ctx, profile, true);
    auto *gv = new GlobalVariable(M, init->getType(), true,
                                  GlobalValue::WeakODRLinkage, init,
                                  "__encbound_instrumented");
    gv->setSection(".encbound.audit");
    gv->setAlignment(Align(1));
    appendToUsed(M, {gv});
    return true;
}

// Explicit acceptance: unlisted intrinsics are unsupported even if LLVM says
// they do not access memory. Pointer-sensitive and ABI effects need review too.
bool isAdmittedValueIntrinsic(const IntrinsicInst &II) {
    switch (II.getIntrinsicID()) {
    case Intrinsic::stacksave:
    case Intrinsic::stackrestore:
        return VLAOption;
    case Intrinsic::dbg_declare:
    case Intrinsic::dbg_value:
    case Intrinsic::dbg_label:
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::assume:
    case Intrinsic::experimental_noalias_scope_decl: // removed before verification
    case Intrinsic::trap: // terminal no-exception library failure
    case Intrinsic::expect:
    case Intrinsic::expect_with_probability:
    case Intrinsic::smax:
    case Intrinsic::smin:
    case Intrinsic::umax:
    case Intrinsic::umin:
    case Intrinsic::abs:
    // Selected application dtoa: pure floating-point values, no memory or
    // pointer arguments. fmuladd preserves LLVM's optional contraction rule.
    case Intrinsic::fabs:
    case Intrinsic::fmuladd:
    // Recompiled application rint/strtod: floating value/sign/classification
    // only. Neither intrinsic accepts pointers or accesses memory/SDK state.
    case Intrinsic::copysign:
    case Intrinsic::is_fpclass:
    case Intrinsic::bswap:
    case Intrinsic::bitreverse:
    case Intrinsic::ctpop:
    case Intrinsic::ctlz:
    case Intrinsic::cttz:
    // mbedTLS SHA-256 rotates lower to funnel shifts. Integer values only;
    // neither intrinsic reads memory nor accepts pointers or changes authority.
    case Intrinsic::fshl:
    case Intrinsic::fshr:
    case Intrinsic::ucmp: // pure integer three-way comparisons from libc++ string
    case Intrinsic::scmp:
    /*
     * Saturating integer add/subtract (E2/LZ4 admission). These are pure
     * value-only integer operations: no memory, no pointer operands and no
     * control flow. Vector forms such as llvm.usub.sat.v4i32 are included, so
     * the scalar and vector overloads share this one admission rule.
     */
    case Intrinsic::sadd_sat:
    case Intrinsic::uadd_sat:
    case Intrinsic::ssub_sat:
    case Intrinsic::usub_sat:
        return true;
    /*
     * Unsigned multiply with overflow. Value-only: returns a two-field struct
     * of integers, accepts no pointers and accesses no memory. mini-gmp's
     * mpn_mul_1 overflow check is lowered to this intrinsic by the -O2
     * frontend (BotScreen integration). Like the saturating group above it
     * changes no authority and is checked by encbound-verify.
     */
    case Intrinsic::umul_with_overflow:
        return true;
    case Intrinsic::smul_with_overflow:
        return VLAOption; // value-only signed sizing normalized before optimization
    case Intrinsic::eh_typeid_for:
        return CxxEHOption;
    // libc++'s O0 string bodies retain __builtin_constant_p. This query
    // returns one bit of compile-time knowledge and performs no memory access.
    case Intrinsic::is_constant:
        return true;
    default:
        return false;
    }
}

// These instructions only propagate values or select ordinary control flow.
// Memory/calls/allocas are handled separately. Unknown opcodes fail closed.
bool isAdmittedValueInstruction(const Instruction &I) {
    switch (I.getOpcode()) {
    case Instruction::Ret: case Instruction::Br: case Instruction::Switch:
    case Instruction::Unreachable:
    case Instruction::FNeg:
    case Instruction::Add: case Instruction::FAdd:
    case Instruction::Sub: case Instruction::FSub:
    case Instruction::Mul: case Instruction::FMul:
    case Instruction::UDiv: case Instruction::SDiv: case Instruction::FDiv:
    case Instruction::URem: case Instruction::SRem: case Instruction::FRem:
    case Instruction::Shl: case Instruction::LShr: case Instruction::AShr:
    case Instruction::And: case Instruction::Or: case Instruction::Xor:
    case Instruction::GetElementPtr:
    case Instruction::Trunc: case Instruction::ZExt: case Instruction::SExt:
    case Instruction::FPToUI: case Instruction::FPToSI:
    case Instruction::UIToFP: case Instruction::SIToFP:
    case Instruction::FPTrunc: case Instruction::FPExt:
    case Instruction::PtrToInt: case Instruction::IntToPtr:
    case Instruction::BitCast:
    case Instruction::ICmp: case Instruction::FCmp:
    case Instruction::PHI: case Instruction::Select: case Instruction::Freeze:
    case Instruction::ExtractElement: case Instruction::InsertElement:
    case Instruction::ShuffleVector:
    case Instruction::ExtractValue: case Instruction::InsertValue:
        return true;
    default:
        return false;
    }
}

bool unsupportedType(Type *T) {
    if (T->isScalableTy() || T->isTargetExtTy()) return true;
    if (auto *P = dyn_cast<PointerType>(T)) return P->getAddressSpace() != 0;
    if (auto *V = dyn_cast<VectorType>(T)) return unsupportedType(V->getElementType());
    if (auto *A = dyn_cast<ArrayType>(T)) return unsupportedType(A->getElementType());
    if (auto *S = dyn_cast<StructType>(T)) {
        for (Type *E : S->elements()) if (unsupportedType(E)) return true;
    }
    return false;
}

// Runtime helpers the compiler inserts itself (mint, checks). Application
// source calls to any `encbound_*` symbol are rejected: the pass's own calls
// are created after the input call scan, so an input call to one is app code.
bool isPrivilegedHelper(StringRef name) { return name.starts_with("encbound_"); }

// Non-local control transfer is not admitted in the first subset (docs/legacy/steps/04).
bool isSetjmpLike(StringRef name) {
    return name == "setjmp" || name == "_setjmp" || name == "__sigsetjmp" ||
           name == "longjmp" || name == "_longjmp" || name == "siglongjmp";
}

// Application/dependency TLS definitions must fail admission (owner decision
// 2026-09-27); trusted SDK/runtime TLS is in objects not given to this pass.
void rejectThreadLocalGlobals(Module &M) {
    for (GlobalVariable &GV : M.globals()) {
        if (!GV.isThreadLocal()) {
            continue;
        }
        std::string msg;
        raw_string_ostream os(msg);
        os << "ENCBound: unsupported thread-local (TLS) definition: " << GV;
        report_fatal_error(Twine(os.str()));
    }
}

// Admitted externals and their optional checked-adapter redirection. Each
// non-comment line of the admitted-symbols file is either
//     symbol
// (admit the application/dependency external as written) or
//     symbol = adapter
// (retarget instrumented application call sites for `symbol` to `adapter`).
// The redirection target is expected to be a trusted checked adapter. SDK
// internal calls are not seen by this pass, so only application call sites are
// retargeted.
struct AdmittedInventory {
    StringSet<> admitted;
    StringMap<std::string> redirect;
};

const AdmittedInventory &admittedInventory() {
    static AdmittedInventory inventory;
    static bool loaded = false;
    if (loaded) {
        return inventory;
    }
    loaded = true;
    if (AdmittedSymbolsFile.empty()) {
        return inventory;
    }
    auto buffer = MemoryBuffer::getFile(AdmittedSymbolsFile);
    if (!buffer) {
        report_fatal_error(Twine("ENCBound: cannot read admitted-symbols file: ") +
                           AdmittedSymbolsFile);
    }
    SmallVector<StringRef, 128> lines;
    (*buffer)->getBuffer().split(lines, '\n');
    for (StringRef line : lines) {
        line = line.trim();
        if (line.empty() || line.starts_with("#")) {
            continue;
        }
        size_t eq = line.find('=');
        if (eq == StringRef::npos) {
            inventory.admitted.insert(line);
            continue;
        }
        StringRef symbol = line.substr(0, eq).trim();
        StringRef adapter = line.substr(eq + 1).trim();
        if (symbol.empty() || adapter.empty()) {
            report_fatal_error(Twine("ENCBound: malformed admitted-symbols line: ") +
                               line);
        }
        inventory.admitted.insert(symbol);
        inventory.redirect[symbol] = adapter.str();
    }
    return inventory;
}

bool isAdmittedExternal(StringRef name) {
    // No-argument compiler support call on the stack-protector failure path.
    if (name == "__stack_chk_fail") {
        return true;
    }
    return admittedInventory().admitted.contains(name);
}

// --- C1: capability address arithmetic -------------------------------------
// Keep scalar GEP on the admitted integral 64-bit pointer/index layout.
// GEP already computes the required full-width representation arithmetic.
// Clear address/no-wrap promises by default; keeping the original flags is an
// explicit experiment, independent of access instrumentation and decoding.
cl::opt<bool> KeepGEPFlagsOption("encbound-keep-gep-flags", cl::init(false),
    cl::desc("Experiment: retain original GEP inbounds/no-wrap flags"), cl::Hidden);

bool admittedGEP(const GetElementPtrInst &GEP) {
    if (!GEP.getType()->isPointerTy()) {
        return false; // vector-of-pointers result
    }
    for (Value *Idx : GEP.indices()) {
        if (!Idx->getType()->isIntegerTy()) {
            return false; // vector index
        }
    }
    return true;
}

// --- C2: attribute/metadata reconciliation ---------------------------------
//
// Instrumentation inserts calls to the runtime (which reads trusted state and
// may abort), rewrites allocas into minted stack capabilities and retargets
// allocator/library calls. Function, parameter, return and call-site
// descriptions that assert absence of memory effects or ordinary
// dereferenceability of application pointers are therefore no longer justified.
// Remove that bounded set conservatively; ABI-required attributes (calling
// conventions and sign/zero extension) are preserved; implicit-memory ABIs
// such as sret/byref are rejected. The selected
// backend runs with later IR optimization disabled, so this is a correctness
// policy, not a performance tuning.
// Bounded policy sets shared by the sanitizer and the post-transform validator.
static const Attribute::AttrKind kFnAttrKinds[] = {
    Attribute::Memory,        Attribute::ReadNone,
    Attribute::ReadOnly,      Attribute::WriteOnly,
    Attribute::NoFree,        Attribute::NoSync,
    Attribute::WillReturn,    Attribute::MustProgress,
    Attribute::Speculatable,  Attribute::AllocSize,
    Attribute::AllocKind,     Attribute::AllocatedPointer,
    Attribute::NoRecurse,     Attribute::NoAlias,
    Attribute::Builtin,
};
static const Attribute::AttrKind kPtrAttrKinds[] = {
    Attribute::NonNull,        Attribute::Dereferenceable,
    Attribute::DereferenceableOrNull, Attribute::Alignment,
    Attribute::NoAlias,        Attribute::NoFree,
    Attribute::Captures,       Attribute::AllocatedPointer,
    Attribute::Initializes,    Attribute::NoUndef,
    Attribute::Writable,       Attribute::DeadOnUnwind,
    Attribute::ReadNone,       Attribute::ReadOnly, Attribute::WriteOnly,
};
// Implicit-memory ABI forms whose accessible-storage promises are not reconciled
// when a call receives a tagged pointer. Rejected rather than only preserved.
static const Attribute::AttrKind kAbiAttrKinds[] = {
    Attribute::ByVal,     Attribute::InAlloca, Attribute::Preallocated,
    Attribute::StructRet, Attribute::ByRef,
};
// Metadata that asserts a semantic fact about a value (dereferenceability,
// non-nullness, alignment, definedness, value range) or about invariance or
// aliasing which instrumentation may invalidate. Removed conservatively. Debug,
// profiling, annotation and loop metadata are non-semantic and kept; the
// selected backend runs with later IR optimization disabled.
static const unsigned kSemanticMetadataKinds[] = {
    LLVMContext::MD_dereferenceable,
    LLVMContext::MD_dereferenceable_or_null,
    LLVMContext::MD_nonnull,
    LLVMContext::MD_align,
    LLVMContext::MD_noundef,
    LLVMContext::MD_invariant_load,
    LLVMContext::MD_invariant_group,
    LLVMContext::MD_alias_scope,
    LLVMContext::MD_noalias,
    LLVMContext::MD_range,
};

void stripSemanticMetadata(Instruction &I) {
    for (unsigned K : kSemanticMetadataKinds) {
        if (I.getMetadata(K) != nullptr) {
            I.setMetadata(K, nullptr);
        }
    }
}

bool hasSemanticMetadata(const Instruction &I) {
    for (unsigned K : kSemanticMetadataKinds) {
        if (I.getMetadata(K) != nullptr) {
            return true;
        }
    }
    return false;
}

void sanitizeTransformedFunction(Function &F) {
    for (Attribute::AttrKind K : kFnAttrKinds) {
        F.removeFnAttr(K);
    }
    for (Attribute::AttrKind K : kPtrAttrKinds) {
        F.removeRetAttr(K);
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            F.removeParamAttr(i, K);
        }
    }
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            stripSemanticMetadata(I);
            auto *CB = dyn_cast<CallBase>(&I);
            if (CB == nullptr) {
                continue;
            }
            for (Attribute::AttrKind K : kPtrAttrKinds) {
                CB->removeRetAttr(K);
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    CB->removeParamAttr(i, K);
                }
            }
            // This removes explicit call-site promises only. Intrinsics retain
            // their mandatory contract on the canonical declaration below.
            for (Attribute::AttrKind K : kFnAttrKinds) {
                CB->removeFnAttr(K);
            }
        }
    }
}

// InstCombine can infer new call-site attributes (for example nonnull on a
// raw stack reservation). Reapply the existing conservative output policy;
// this pass never adds/removes checks or relaxes their verifier.
struct ENCBoundPostInstCombinePass : PassInfoMixin<ENCBoundPostInstCombinePass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        for (Function &F : M) {
            if (F.isIntrinsic())
                F.setAttributes(Intrinsic::getAttributes(
                    M.getContext(), F.getIntrinsicID(), F.getFunctionType()));
            else
                sanitizeTransformedFunction(F);
            if (!KeepGEPFlagsOption)
                for (Instruction &I : instructions(F))
                    if (auto *G = dyn_cast<GetElementPtrInst>(&I))
                        G->setNoWrapFlags(GEPNoWrapFlags::none());
        }
        return PreservedAnalyses::none();
    }
    static bool isRequired() { return true; }
};

// Retarget an application call to an external symbol named in the admitted
// inventory to its checked adapter. Only declarations are redirected; a
// definition in the module is application code and stays as written.
bool redirectFromInventory(Module &M, CallBase *CI) {
    Function *callee = CI->getCalledFunction();
    if (callee == nullptr || !callee->isDeclaration()) {
        return false;
    }
    const AdmittedInventory &inventory = admittedInventory();
    auto it = inventory.redirect.find(callee->getName());
    if (it == inventory.redirect.end()) {
        return false;
    }
    CI->setCalledFunction(
        M.getOrInsertFunction(StringRef(it->second), CI->getFunctionType()));
    return true;
}

#include "encbound_integration.h"
#include "encbound_variadics.h"
#include "encbound_globals.h"
#include "encbound_lifecycle.h"
#include "encbound_vla.h"
#include "encbound_cxx_eh.h"

struct ENCBoundPass : PassInfoMixin<ENCBoundPass> {
    SmallPtrSet<Function *, 32> Routed;
    GlobalTransform Globals;


    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        if (M.getTargetTriple().getArch() != Triple::x86_64 ||
            M.getDataLayout().getPointerSizeInBits() != 64)
            report_fatal_error("ENCBound: unsupported target (requires x86-64)");
        if (!M.getModuleInlineAsm().empty() || (!VirtualsOption && !M.alias_empty()) || !M.ifunc_empty())
            report_fatal_error("ENCBound: unsupported module asm/alias/ifunc");
        if (M.getNamedValue("__encbound_instrumented"))
            report_fatal_error("ENCBound: input already has instrumentation marker");
        validateFunctionAliases(M);
        rejectThreadLocalGlobals(M);
        for (GlobalVariable &GV : M.globals()) {
            if (GV.getName().starts_with("__encbound_") ||
                GV.getSection().starts_with("encbound_g") ||
                GV.getSection().starts_with(".encbound"))
                report_fatal_error("ENCBound: reserved global capability storage in input");
            if (unsupportedType(GV.getValueType()) || GV.getAddressSpace() != 0)
                report_fatal_error("ENCBound: unsupported global type/address space");
        }
        if (CxxEHOption) prepareCxxEH(M, Routed);
        validateStartupLists(M);
        routeLifecycleRegistration(M, Routed);
        if (CallbacksOption || CxxAllocationOption) routeServiceReferences(M, Routed);
        normalizeVariadicABI(M, Routed);
        if (AggregateABIOption) normalizeAggregateABI(M, Routed);
        Globals.run(M);
        if (CxxLifecycleOption) markLifecycle(M);
        // Helpers appended while processing functions are declarations only.
        for (Function &F : M) if (!F.isDeclaration()) runFunction(F);
        // Apply the same attribute policy to remaining external declarations so
        // a sanitized call site cannot be paired with an unsanitized callee
        // declaration (C2). Reset intrinsic declarations to LLVM's mandatory
        // contract so optional pointer promises cannot enter via a declaration.
        for (Function &F : M) {
            if (F.isIntrinsic())
                F.setAttributes(Intrinsic::getAttributes(
                    M.getContext(), F.getIntrinsicID(), F.getFunctionType()));
            else if (F.isDeclaration())
                sanitizeTransformedFunction(F);
        }
        addInstrumentedMarker(M);
        return PreservedAnalyses::none();
    }

    void runFunction(Function &F) {
        if (F.isDeclaration()) {
            return;
        }
        Module *M = F.getParent();
        const DataLayout &DL = M->getDataLayout();
        LLVMContext &Ctx = M->getContext();
        Type *I64 = Type::getInt64Ty(Ctx);
        Type *I32 = Type::getInt32Ty(Ctx);
        PointerType *PtrTy = PointerType::get(Ctx, 0);

        FunctionCallee require = M->getOrInsertFunction(
            "encbound_require",
            FunctionType::get(I64, {I64, I64, I32}, false));
        FunctionCallee mint = M->getOrInsertFunction(
            "encbound_stack_mint",
            FunctionType::get(I64, {PtrTy, I64}, false));

        if (F.isVarArg())
            report_fatal_error(Twine("ENCBound: unsupported variadic function: ") + F.getName());
        for (Argument &A : F.args()) {
            if (unsupportedType(A.getType()) || A.hasByValAttr() ||
                A.hasInAllocaAttr() || A.hasPreallocatedAttr() ||
                A.hasStructRetAttr() || A.hasByRefAttr())
                report_fatal_error(Twine("ENCBound: unsupported argument ABI/type: ") + F.getName());
        }

        if (CxxEHOption) normalizeCxxEHTokens(F);
        dynamic_stack::normalize(F);
        SmallVector<AllocaInst *, 16> allocas;
        SmallVector<Instruction *, 64> accesses;
        SmallVector<CallBase *, 16> calls;
        bool changed = false;
        SmallVector<Instruction *, 16> lifetimes;
        SmallVector<IntrinsicInst *, 8> assumes;
        SmallVector<GetElementPtrInst *, 32> geps;

        for (Instruction &I : instructions(F)) {
            if (unsupportedType(I.getType()))
                reportUnsupported(&I, "type (scalable/target-specific/address space)");
            for (const Use &U : I.operands())
                if (unsupportedType(U->getType()))
                    reportUnsupported(&I, "operand type");
            if (auto *CB = dyn_cast<CallBase>(&I)) {
                if (CB->hasOperandBundles() && CB->getIntrinsicID()!=Intrinsic::assume)
                    reportUnsupported(&I, "call operand bundles");
                for (unsigned A = 0; A < CB->arg_size(); ++A)
                    for (Attribute::AttrKind K : kAbiAttrKinds)
                        if (CB->paramHasAttr(A, K))
                            reportUnsupported(&I, "implicit memory argument ABI");
            }
            if ((!CxxEHOption && (isa<InvokeInst>(&I) || isa<LandingPadInst>(&I) ||
                isa<ResumeInst>(&I))) || isa<CatchSwitchInst>(&I) ||
                isa<CatchReturnInst>(&I) || isa<CleanupReturnInst>(&I) ||
                isa<FuncletPadInst>(&I)) {
                reportUnsupported(&I, "exception handling");
            } else if (auto *AI = dyn_cast<AllocaInst>(&I)) {
                if (unsupportedType(AI->getAllocatedType()) || AI->getAddressSpace() != 0)
                    reportUnsupported(AI, "alloca type/address space");
                if (!AI->isStaticAlloca() && !VLAOption) {
                    reportUnsupported(AI, "dynamic alloca/VLA");
                }
                if (!AI->use_empty() || !AI->isStaticAlloca()) {
                    allocas.push_back(AI);
                }
            } else if (auto *RMW = dyn_cast<AtomicRMWInst>(&I)) {
                if (!admittedAtomic(I)) reportUnsupported(RMW, "atomicrmw");
                accesses.push_back(RMW);
            } else if (auto *CX = dyn_cast<AtomicCmpXchgInst>(&I)) {
                if (!admittedAtomic(I)) reportUnsupported(CX, "cmpxchg");
                accesses.push_back(CX);
            } else if (isa<FenceInst>(I)) {
                if (!admittedAtomic(I)) reportUnsupported(&I, "fence");
            } else if (auto *LI = dyn_cast<LoadInst>(&I)) {
                if (LI->isAtomic() && !admittedAtomic(I)) {
                    reportUnsupported(LI, "atomic load");
                }
                accesses.push_back(LI);
            } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
                if (SI->isAtomic() && !admittedAtomic(I)) {
                    reportUnsupported(SI, "atomic store");
                }
                accesses.push_back(SI);
            } else if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
                if (II->getIntrinsicID() == Intrinsic::memcpy ||
                    II->getIntrinsicID() == Intrinsic::memmove ||
                    II->getIntrinsicID() == Intrinsic::memset) {
                    accesses.push_back(II);
                } else if (!isAdmittedValueIntrinsic(*II)) {
                    reportUnsupported(II, "intrinsic");
                } else if (II->getIntrinsicID() == Intrinsic::lifetime_start ||
                           II->getIntrinsicID() == Intrinsic::lifetime_end) {
                    // The complete reserved slot lives until function return;
                    // do not leave lifetime markers referring to a capability.
                    lifetimes.push_back(II);
                } else if (II->getIntrinsicID() == Intrinsic::assume ||
                           II->getIntrinsicID() == Intrinsic::experimental_noalias_scope_decl) {
                    // Optimization-only assumptions are not established to hold
                    // for tagged values after rewriting; drop them (C2).
                    assumes.push_back(II);
                }
            } else if (auto *GI = dyn_cast<GetElementPtrInst>(&I)) {
                geps.push_back(GI);
            } else if (auto *CI = dyn_cast<CallBase>(&I)) {
                calls.push_back(CI);
            } else if (CxxEHOption && (isa<LandingPadInst>(&I) || isa<ResumeInst>(&I))) {
                // Token confinement is checked separately, before and after rewriting.
            } else if (!isAdmittedValueInstruction(I)) {
                reportUnsupported(&I, "instruction");
            }
        }

        for (Instruction *I : lifetimes) I->eraseFromParent();
        for (Instruction *I : assumes) I->eraseFromParent();
        for (AllocaInst *AI : allocas) {
            if (AI->isStaticAlloca()) rewriteAlloca(*M, DL, *AI, mint);
            else dynamic_stack::rewrite(*M, *AI);
            changed = true;
        }
        // Rewritten allocas now feed capabilities into the original GEPs.
        // Address formation stays separate from checking/decoding at access.
        for (GetElementPtrInst *GI : geps) {
            if (!admittedGEP(*GI)) {
                reportUnsupported(GI, "vector GEP address calculation");
            }
            if (!KeepGEPFlagsOption) GI->setNoWrapFlags(GEPNoWrapFlags::none());
            changed = true;
        }
        for (Instruction *I : accesses) {
            changed |= instrument(*M, DL, I, require, I64);
        }
        for (CallBase *CI : calls) {
            if (auto *Call=dyn_cast<CallInst>(CI); Call && Globals.Accessors.contains(Call)) continue;
            if (CI->isInlineAsm()) {
                reportUnsupported(CI, "inline asm");
            }
            if (CI->isIndirectCall()) {
                if (!CallbacksOption || !simpleCallbackABI(*CI))
                    reportUnsupported(CI, "indirect call ABI (enable admitted callbacks)");
                continue;
            }
            Function *callee = CI->getCalledFunction();
            if (callee == nullptr) {
                reportUnsupported(CI, "call with unresolved target");
            }
            if (Routed.contains(callee)) continue;
            if (isPrivilegedHelper(callee->getName()) || isSetjmpLike(callee->getName()))
                reportUnsupported(CI, "privileged helper or setjmp/longjmp call");
            if (redirectStringFormat(*M, CI)) {
                changed = true;
                continue;
            }
            if (callee->isVarArg()) reportUnsupported(CI, "variadic call");
            if (redirectKnownCall(*M, CI)) {
                changed = true;
                continue;
            }
            if (redirectFromInventory(*M, CI)) {
                changed = true;
                continue;
            }
            if (callee->isDeclaration()) {
                if (isSetjmpLike(callee->getName())) {
                    reportUnsupported(CI, "setjmp/longjmp");
                }
                if (isPrivilegedHelper(callee->getName())) {
                    reportUnsupported(CI, "privileged helper call");
                }
                if (!isAdmittedExternal(callee->getName())) {
                    reportUnsupported(CI, "unapproved external call");
                }
            }
        }
        sanitizeTransformedFunction(F);
        (void)changed;
    }

    static bool isRequired() { return true; }

  private:
    static void reportUnsupported(Instruction *I, const char *what) {
        std::string msg;
        raw_string_ostream os(msg);
        os << "ENCBound: unsupported " << what << " in "
           << I->getFunction()->getName() << ": " << *I;
        if (I->getDebugLoc()) {
            os << "\n  at " << I->getDebugLoc();
        }
        report_fatal_error(Twine(os.str()));
    }

    static Value *insertCheckIn(IRBuilderBase &B, Module &M,
                                Function *requireFn, Value *pointer, Value *width,
                                unsigned kind) {
        Type *I64 = Type::getInt64Ty(M.getContext());
        Type *I32 = Type::getInt32Ty(M.getContext());
        Value *bits = B.CreatePtrToInt(pointer, I64);
        if (!width->getType()->isIntegerTy(64)) {
            width = B.CreateZExtOrTrunc(width, I64);
        }
        Value *raw = B.CreateCall(requireFn,
                                  {bits, width, ConstantInt::get(I32, kind)});
        return B.CreateIntToPtr(raw, pointer->getType());
    }

    static Value *insertCheck(Module &M, Instruction *At, Function *requireFn,
                              Value *pointer, Value *width, unsigned kind) {
        IRBuilder<> B(At);
        return insertCheckIn(B, M, requireFn, pointer, width, kind);
    }

    // Memory intrinsics take a runtime length. A zero length must not reserve or
    // decode an address (runtime zero-width checks abort), but a nonzero length
    // must be checked strictly. For a dynamic length, branch on len != 0 and
    // pass the original (still tagged) operand on the no-op path; the intrinsic
    // then performs no access. A constant zero intrinsic is left untouched.
    static bool instrumentMemIntrinsic(Module &M, IntrinsicInst *II,
                                       Function *requireFn) {
        LLVMContext &Ctx = M.getContext();
        bool isMemset = II->getIntrinsicID() == Intrinsic::memset;
        Value *len = II->getArgOperand(2);
        Value *dst = II->getArgOperand(0);
        Value *src = isMemset ? nullptr : II->getArgOperand(1);

        if (auto *CI = dyn_cast<ConstantInt>(len)) {
            if (CI->isZero()) {
                return false;
            }
            II->setArgOperand(
                0, insertCheck(M, II, requireFn, dst, len, kAccessWrite));
            if (src != nullptr) {
                II->setArgOperand(
                    1, insertCheck(M, II, requireFn, src, len, kAccessRead));
            }
            return true;
        }

        Value *nonzero;
        {
            IRBuilder<> B(II);
            nonzero = B.CreateICmpNE(len, ConstantInt::get(len->getType(), 0),
                                     "encbound.mem.nonzero");
        }
        Function *F = II->getFunction();
        BasicBlock *orig = II->getParent();
        BasicBlock *checkBB =
            BasicBlock::Create(Ctx, "encbound.mem.check", F);
        BasicBlock *cont = orig->splitBasicBlock(II, "encbound.mem.cont");
        orig->getTerminator()->eraseFromParent();
        IRBuilder<>(orig).CreateCondBr(nonzero, checkBB, cont);

        Value *checkedDst;
        Value *checkedSrc = nullptr;
        {
            IRBuilder<> CB(checkBB);
            checkedDst = insertCheckIn(CB, M, requireFn, dst, len, kAccessWrite);
            if (src != nullptr) {
                checkedSrc = insertCheckIn(CB, M, requireFn, src, len, kAccessRead);
            }
            CB.CreateBr(cont);
        }
        {
            IRBuilder<> PB(cont, cont->getFirstInsertionPt());
            PHINode *dstPhi =
                PB.CreatePHI(dst->getType(), 2, "encbound.mem.dst");
            dstPhi->addIncoming(dst, orig);
            dstPhi->addIncoming(checkedDst, checkBB);
            II->setArgOperand(0, dstPhi);
            if (src != nullptr) {
                PHINode *srcPhi =
                    PB.CreatePHI(src->getType(), 2, "encbound.mem.src");
                srcPhi->addIncoming(src, orig);
                srcPhi->addIncoming(checkedSrc, checkBB);
                II->setArgOperand(1, srcPhi);
            }
        }
        return true;
    }

    static bool instrument(Module &M, const DataLayout &DL, Instruction *I,
                           FunctionCallee require, Type *I64) {
        auto *requireFn = cast<Function>(require.getCallee());
        Type *I32 = Type::getInt32Ty(M.getContext());
        (void)I32;
        if (auto *LI = dyn_cast<LoadInst>(I)) {
            uint64_t bytes = DL.getTypeStoreSize(LI->getType());
            if (bytes == 0) {
                return false;
            }
            LI->setOperand(LI->getPointerOperandIndex(),
                           insertCheck(M, LI, requireFn, LI->getPointerOperand(),
                                       ConstantInt::get(I64, bytes),
                                       kAccessRead));
            return true;
        }
        if (auto *SI = dyn_cast<StoreInst>(I)) {
            uint64_t bytes = DL.getTypeStoreSize(SI->getValueOperand()->getType());
            if (bytes == 0) {
                return false;
            }
            SI->setOperand(
                SI->getPointerOperandIndex(),
                insertCheck(M, SI, requireFn, SI->getPointerOperand(),
                            ConstantInt::get(I64, bytes), kAccessWrite));
            return true;
        }
        if (auto *R = dyn_cast<AtomicRMWInst>(I)) {
            R->setOperand(0, insertCheck(M, I, requireFn, R->getPointerOperand(),
                ConstantInt::get(I64, DL.getTypeStoreSize(R->getValOperand()->getType())), kAccessReadWrite));
            return true;
        }
        if (auto *C = dyn_cast<AtomicCmpXchgInst>(I)) {
            C->setOperand(0, insertCheck(M, I, requireFn, C->getPointerOperand(),
                ConstantInt::get(I64, DL.getTypeStoreSize(C->getCompareOperand()->getType())), kAccessReadWrite));
            return true;
        }
        if (auto *II = dyn_cast<IntrinsicInst>(I)) {
            return instrumentMemIntrinsic(M, II, requireFn);
        }
        return false;
    }

    static void rewriteAlloca(Module &M, const DataLayout &DL, AllocaInst &AI,
                              FunctionCallee mint) {
        auto *count = dyn_cast<ConstantInt>(AI.getArraySize());
        if (count == nullptr) {
            reportUnsupported(&AI, "dynamic alloca/VLA");
            return;
        }
        uint64_t element = DL.getTypeAllocSize(AI.getAllocatedType());
        if (count->getValue().getActiveBits() > 64 || element == 0 ||
            count->getZExtValue() > (1ull << 30) / element)
            reportUnsupported(&AI, "unsupported stack object size");
        uint64_t bytes = element * count->getZExtValue();
        uint64_t align = AI.getAlign().value();
        uint64_t need = std::max(bytes, std::max<uint64_t>(align, 16));
        if (need > (1ull << 30)) reportUnsupported(&AI, "unsupported stack alignment/size");
        uint64_t slot = PowerOf2Ceil(need);
        if (bytes == 0 || slot > (1ull << 30)) {
            reportUnsupported(&AI, "unsupported stack object size");
            return;
        }

        LLVMContext &Ctx = M.getContext();
        Type *I8 = Type::getInt8Ty(Ctx);
        Type *I64 = Type::getInt64Ty(Ctx);
        PointerType *PtrTy = PointerType::get(Ctx, 0);
        IRBuilder<> B(&AI);
        AllocaInst *slotAlloca =
            B.CreateAlloca(I8, ConstantInt::get(I64, slot), "encbound.slot");
        slotAlloca->setAlignment(Align(slot));
        Value *cap = B.CreateCall(mint, {slotAlloca, ConstantInt::get(I64, slot)},
                                  "encbound.cap");
        Value *capPtr = B.CreateIntToPtr(cap, PtrTy, "encbound.obj");
        AI.replaceAllUsesWith(capPtr);
        AI.eraseFromParent();
    }

    // Admit only the exact format used by the selected Juliet cases. Checking
    // both the declaration and call ABI prevents malformed prototypes from
    // becoming trusted calls. The format remains an argument, checked again by
    // the adapter. No general varargs or mutable/dynamic formats are admitted.
    static bool redirectStringFormat(Module &M, CallBase *CI) {
        Function *callee = CI->getCalledFunction();
        if (!callee || callee->getName() != "snprintf") return false;
        LLVMContext &Ctx = M.getContext();
        Type *Ptr = PointerType::get(Ctx, 0);
        Type *I64 = Type::getInt64Ty(Ctx);
        Type *I32 = Type::getInt32Ty(Ctx);
        FunctionType *Original = FunctionType::get(I32, {Ptr, I64, Ptr}, true);
        if (!callee->isDeclaration() || callee->getFunctionType() != Original ||
            CI->getFunctionType() != Original || CI->arg_size() != 4 ||
            CI->getCallingConv() != CallingConv::C ||
            callee->getCallingConv() != CallingConv::C ||
            CI->getArgOperand(3)->getType() != Ptr)
            reportUnsupported(CI, "snprintf ABI or argument count");
        auto *Format = dyn_cast<GlobalVariable>(CI->getArgOperand(2));
        auto *Bytes = Format && Format->isConstant() && Format->hasInitializer()
            ? dyn_cast<ConstantDataArray>(Format->getInitializer()) : nullptr;
        if (!Bytes || !Bytes->isCString() || Bytes->getAsCString() != "%s")
            reportUnsupported(CI, "snprintf format (requires constant literal %s)");
        FunctionType *Fixed = FunctionType::get(I32, {Ptr, I64, Ptr, Ptr}, false);
        CI->setCalledFunction(M.getOrInsertFunction("encbound_snprintf_string", Fixed));
        return true;
    }

    // Application call sites for the allocation and library services with a
    // checked adapter are retargeted here (docs/legacy/steps/05-boundaries.md item 3). SDK
    // internal calls are not passed through this pass.
    static bool redirectKnownCall(Module &M, CallBase *CI) {
        Function *callee = CI->getCalledFunction();
        if (callee == nullptr) {
            return false;
        }
        if (!callee->isDeclaration()) return false;
        if (admittedInventory().admitted.contains(callee->getName()) &&
            !admittedInventory().redirect.contains(callee->getName())) return false;
        auto Mapping = serviceMapping(M, callee->getName());
        if (Mapping.first.empty()) return false;
        validateServiceABI(*callee, Mapping.second);
        if (CI->getFunctionType() != Mapping.second ||
            CI->getCallingConv() != CallingConv::C)
            reportUnsupported(CI, "service call ABI");
        CI->setCalledFunction(M.getOrInsertFunction(Mapping.first, Mapping.second));
        return true;
    }
};

// Optional, compiler-private guarded span reuse. Full checks remain the
// fallback at each access; tokens contain no application-readable authority.
struct ENCBoundReusePass : PassInfoMixin<ENCBoundReusePass> {
    struct Group {
        Value *Origin;
        Loop *Scope;
        BasicBlock *Block;
        unsigned Segment;
        SmallVector<CallInst *, 8> Calls;
    };
    static bool loopSafe(Loop *L) {
        if (!L->getLoopPreheader()) return false;
        for (BasicBlock *B : L->blocks())
            for (Instruction &I : *B) if (spanBarrier(I)) return false;
        return true;
    }
    static bool scalarAccess(CallInst *C) {
        if (!C->hasOneUse()) return false;
        auto *IP = dyn_cast<IntToPtrInst>(*C->user_begin());
        if (!IP || !IP->hasOneUse()) return false;
        auto *I = dyn_cast<Instruction>(*IP->user_begin());
        return I && (isa<LoadInst>(I) || isa<StoreInst>(I)) && !spanBarrier(*I);
    }
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        if (CheckReuseOption != "off" && CheckReuseOption != "block" && CheckReuseOption != "loop")
            report_fatal_error("ENCBound: unsupported check reuse mode");
        if (CheckReuseOption == "off") return PreservedAnalyses::all();
        auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
        unsigned Prepared=0, Covered=0;
        auto *I64=Type::getInt64Ty(M.getContext());
        auto *I32=Type::getInt32Ty(M.getContext());
        auto Prepare=M.getOrInsertFunction("encbound_span_prepare",FunctionType::get(I64,{I64},false));
        auto Require=M.getOrInsertFunction("encbound_span_require",FunctionType::get(I64,{I64,I64,I32,I64,I64},false));
        for (Function &F : M) {
            if (F.isDeclaration()) continue;
            auto &DT=FAM.getResult<DominatorTreeAnalysis>(F);
            auto &LI=FAM.getResult<LoopAnalysis>(F);
            SmallVector<Group,16> Groups;
            for (BasicBlock &B : F) {
                unsigned Segment=0;
                for (Instruction &I : B) {
                    if (spanBarrier(I)) ++Segment;
                    if (!namedCall(I,"encbound_require")) continue;
                    auto *C=cast<CallInst>(&I);
                    if (!scalarAccess(C)) continue;
                    Value *Origin=spanOrigin(C->getArgOperand(0));
                    if (!Origin) continue;
                    Loop *Scope=nullptr;
                    if (CheckReuseOption == "loop") {
                        for (Loop *L=LI.getLoopFor(&B); L; L=L->getParentLoop()) {
                            if (!loopSafe(L) || !L->isLoopInvariant(Origin)) continue;
                            auto *Def=dyn_cast<Instruction>(Origin);
                            if (Def && !DT.dominates(Def,L->getLoopPreheader()->getTerminator())) continue;
                            Scope=L;
                        }
                    }
                    Group *G=nullptr;
                    for (auto &Candidate : Groups)
                        if (Candidate.Origin==Origin && Candidate.Scope==Scope &&
                            (Scope || (Candidate.Block==&B && Candidate.Segment==Segment))) {G=&Candidate;break;}
                    if (!G) {
                        Groups.push_back({Origin,Scope,&B,Segment,{}});
                        G=&Groups.back();
                    }
                    G->Calls.push_back(C);
                }
            }
            for (auto &G : Groups) {
                if (!G.Scope && G.Calls.size()<2) continue;
                Instruction *At=G.Scope ? G.Scope->getLoopPreheader()->getTerminator() : G.Calls.front();
                IRBuilder<> B(At);
                Value *Anchor=B.CreatePtrToInt(G.Origin,I64,"encbound.span.anchor");
                Value *Token=B.CreateCall(Prepare,{Anchor},"encbound.span.token");
                ++Prepared;
                for (CallInst *C : G.Calls) {
                    IRBuilder<> CB(C);
                    auto *New=CB.CreateCall(Require,{C->getArgOperand(0),C->getArgOperand(1),C->getArgOperand(2),Anchor,Token});
                    New->setDebugLoc(C->getDebugLoc());
                    C->replaceAllUsesWith(New);C->eraseFromParent();++Covered;
                }
            }
        }
        errs()<<"ENCBound reuse "<<CheckReuseOption<<": "<<Prepared<<" span preparations, "<<Covered<<" guarded access sites\n";
        return PreservedAnalyses::none();
    }
    static bool isRequired() { return true; }
};

// Run after guarded reuse, so covered accesses remove guards as well as full
// checks. Proof failure leaves the existing instrumentation untouched.
struct ENCBoundLocalProofPass : PassInfoMixin<ENCBoundLocalProofPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        if (!LocalProofsOption) return PreservedAnalyses::all();
        unsigned Local=0, Repeated=0;
        for (Function &F : M) for (BasicBlock &B : F) {
            SmallVector<CallInst *,16> Earlier;
            SmallVector<CallInst *,16> Calls;
            for (Instruction &I : B)
                if (namedCall(I,"encbound_require") || namedCall(I,"encbound_span_require"))
                    Calls.push_back(cast<CallInst>(&I));
            for (CallInst *C : Calls) {
                if (!C->hasOneUse()) continue;
                auto *IP=dyn_cast<IntToPtrInst>(*C->user_begin());
                if (!IP || !IP->hasOneUse()) continue;
                auto *Access=dyn_cast<Instruction>(*IP->user_begin());
                uint64_t Width=0; unsigned Kind=0;
                if (!Access || !scalarProofAccess(Access,IP,Width,Kind) || !clearProofScope(C,Access)) continue;
                auto A=constantAddress(C->getArgOperand(0));
                Value *Raw=nullptr; uint64_t Offset=0;
                auto *Mint=dyn_cast<CallInst>(A.Base);
                AllocaInst *Slot=nullptr; uint64_t Size=0;
                IRBuilder<> Builder(C);
                if (mintedLocal(Mint,Slot,Size) && A.Offset<=Size && Width<=Size-A.Offset &&
                    clearProofScope(Mint,Access)) {
                    Raw=Builder.CreatePtrToInt(Slot,Type::getInt64Ty(M.getContext()),"encbound.proven.local");
                    Offset=A.Offset; ++Local;
                } else {
                    for (CallInst *Prev : Earlier) {
                        auto P=constantAddress(Prev->getArgOperand(0));
                        auto *W=dyn_cast<ConstantInt>(Prev->getArgOperand(1));
                        auto *K=dyn_cast<ConstantInt>(Prev->getArgOperand(2));
                        uint64_t Delta=A.Offset-P.Offset;
                        if (A.Base==P.Base && W && K && K->getZExtValue()==Kind &&
                            Delta<=W->getZExtValue() && Width<=W->getZExtValue()-Delta &&
                            clearProofScope(Prev,Access)) {
                            Raw=Prev; Offset=Delta; ++Repeated; break;
                        }
                    }
                }
                if (!Raw) {Earlier.push_back(C); continue;}
                if (Offset) Raw=Builder.CreateAdd(Raw,Builder.getInt64(Offset),"encbound.proven.offset");
                auto *Address=Builder.CreateIntToPtr(Raw,IP->getType(),"encbound.proven.address");
                IP->replaceAllUsesWith(Address); IP->eraseFromParent(); C->eraseFromParent();
            }
        }
        SmallVector<Instruction *,16> Dead;
        for (Function &F : M) for (Instruction &I : instructions(F))
            if (namedCall(I,"encbound_span_prepare") && I.use_empty()) Dead.push_back(&I);
        for (Instruction *I : Dead) I->eraseFromParent();
        errs()<<"ENCBound local proofs: "<<Local<<" local accesses, "<<Repeated<<" covered accesses elided\n";
        return PreservedAnalyses::none();
    }
    static bool isRequired() { return true; }
};

// --- C3: mandatory post-transform validation --------------------------------
//
// Validate the admitted output pattern by operand/type/def-use structure rather
// than names, counts or metadata stamps. Runs as `encbound-verify` in the
// protected driver after `encbound` and before LLVM's own verifier and code
// generation. It is scoped to this transform, not a general binary proof.
struct ENCBoundVerifyPass : PassInfoMixin<ENCBoundVerifyPass> {

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
        validateStartupLists(M);
        verifyCxxEHModule(M);
        const DataLayout &DL = M.getDataLayout();
        FunctionAnalysisManager &FAM =
            MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
        for (Function &F : M) {
            if (F.isIntrinsic()) {
                if (F.getAttributes() != Intrinsic::getAttributes(
                        M.getContext(), F.getIntrinsicID(), F.getFunctionType()))
                    failFn(F, "noncanonical intrinsic declaration attributes");
            } else {
                verifySanitizedSignature(F);
            }
            if (F.isDeclaration()) {
                continue;
            }
            verifyAggregateCopies(F);
            verifyCxxEH(F, true);
            dynamic_stack::verify(F);
            DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(F);
            for (Instruction &I : instructions(F)) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (namedCall(I, "encbound_global_cap")) {
                        auto *G = CI->arg_size()==1 ? dyn_cast<GlobalVariable>(CI->getArgOperand(0)) : nullptr;
                        auto *I64=Type::getInt64Ty(M.getContext()); auto *P=PointerType::get(M.getContext(),0);
                        if (!G || !G->getName().starts_with("__encbound_gcap_") || G->getValueType()!=I64 ||
                            (G->hasInitializer() && G->getSection()!="encbound_gcaps") ||
                            CI->getFunctionType()!=FunctionType::get(I64,{P},false))
                            fail(F,I,"invalid global capability accessor");
                    }
                    if (CI->isIndirectCall() && (!CallbacksOption || !simpleCallbackABI(*CI)))
                        fail(F, I, "unadmitted indirect call ABI");
                    Function *Callee = CI->getCalledFunction();
                    if (Callee && (Callee->getName() == "encbound_require" ||
                                   Callee->getName() == "encbound_span_require")) {
                        verifyRawResult(F, *CI);
                        if (Callee->getName() == "encbound_span_require")
                            verifySpanUse(F,*CI,DT,FAM.getResult<LoopAnalysis>(F));
                    }
                    if (Callee && Callee->getName() == "encbound_span_prepare")
                        verifySpanToken(F,*CI);
                }
                if (ProtectedGlobalsOption)
                    for (Value *V : I.operands())
                        if (auto *K=dyn_cast<Constant>(V); K && containsProtectedGlobal(K))
                            fail(F,I,"raw protected global reference survived transformation");
                if (LocalProofsOption) {
                    auto *R=dyn_cast<PtrToIntInst>(&I);
                    if (R && isa<AllocaInst>(R->getPointerOperand()) && !localProofRoot(R))
                        fail(F,I,"invalid or escaped local proof reservation");
                }
                if (hasSemanticMetadata(I)) {
                    fail(F, I, "semantic or aliasing metadata survived the transform");
                }
                if (auto *G = dyn_cast<GetElementPtrInst>(&I)) {
                    if (!admittedGEP(*G)) fail(F,I,"unsupported GEP address calculation");
                    if (!KeepGEPFlagsOption && G->getNoWrapFlags()!=GEPNoWrapFlags::none())
                        fail(F,I,"GEP address promise survived the transform");
                }
                bool Atomic = isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I) || isa<FenceInst>(I);
                if (auto *L = dyn_cast<LoadInst>(&I)) Atomic |= L->isAtomic();
                if (auto *S = dyn_cast<StoreInst>(&I)) Atomic |= S->isAtomic();
                if (Atomic && !admittedAtomic(I)) fail(F,I,"unsupported atomic shape");
                if (auto *R = dyn_cast<AtomicRMWInst>(&I)) {
                    checkAccess(F,I,R->getPointerOperand(),DL.getTypeStoreSize(R->getValOperand()->getType()),kAccessReadWrite,DT,false);
                    continue;
                }
                if (auto *C = dyn_cast<AtomicCmpXchgInst>(&I)) {
                    checkAccess(F,I,C->getPointerOperand(),DL.getTypeStoreSize(C->getCompareOperand()->getType()),kAccessReadWrite,DT,false);
                    continue;
                }
                if (auto *LI = dyn_cast<LoadInst>(&I)) {
                    uint64_t bytes = DL.getTypeStoreSize(LI->getType());
                    if (bytes != 0) {
                        checkAccess(F, I, LI->getPointerOperand(), bytes,
                                    kAccessRead, DT, /*allowPhi=*/false);
                    }
                    continue;
                }
                if (auto *SI = dyn_cast<StoreInst>(&I)) {
                    uint64_t bytes =
                        DL.getTypeStoreSize(SI->getValueOperand()->getType());
                    if (bytes != 0) {
                        checkAccess(F, I, SI->getPointerOperand(), bytes,
                                    kAccessWrite, DT, /*allowPhi=*/false);
                    }
                    continue;
                }
                auto *II = dyn_cast<IntrinsicInst>(&I);
                if (II == nullptr) {
                    continue;
                }
                unsigned id = II->getIntrinsicID();
                if (id == Intrinsic::assume || id == Intrinsic::experimental_noalias_scope_decl)
                    fail(F,I,"optimization-only assumption survived the transform");
                if (id != Intrinsic::memcpy && id != Intrinsic::memmove &&
                    id != Intrinsic::memset) {
                    continue;
                }
                Value *len = II->getArgOperand(2);
                if (auto *C = dyn_cast<ConstantInt>(len)) {
                    if (C->isZero()) {
                        continue; // documented zero-length no-op path
                    }
                }
                checkAccessLen(F, I, II->getArgOperand(0), len, kAccessWrite,
                               DT);
                if (id != Intrinsic::memset) {
                    checkAccessLen(F, I, II->getArgOperand(1), len, kAccessRead,
                                   DT);
                }
            }
        }
        return PreservedAnalyses::all();
    }

    static bool isRequired() { return true; }

  private:
    static void verifySpanToken(Function &F, CallInst &C) {
        auto *I64=Type::getInt64Ty(F.getContext());
        if (C.getFunctionType()!=FunctionType::get(I64,{I64},false) ||
            C.getCallingConv()!=CallingConv::C || C.hasOperandBundles() || C.use_empty())
            fail(F,C,"invalid span preparation ABI or orphan token");
        for (Use &U : C.uses()) {
            auto *User=dyn_cast<CallInst>(U.getUser());
            if (!User || !namedCall(*User,"encbound_span_require") ||
                User->arg_size()!=5 || !User->isArgOperand(&U) ||
                User->getArgOperandNo(&U)!=4 || User->getArgOperand(3)!=C.getArgOperand(0))
                fail(F,C,"span token escaped or anchor mismatch");
        }
    }
    static void verifySpanUse(Function &F, CallInst &C, DominatorTree &DT, LoopInfo &LI) {
        auto *I64=Type::getInt64Ty(F.getContext());
        auto *I32=Type::getInt32Ty(F.getContext());
        if (C.getFunctionType()!=FunctionType::get(I64,{I64,I64,I32,I64,I64},false) ||
            C.getCallingConv()!=CallingConv::C || C.hasOperandBundles())
            fail(F,C,"invalid guarded span ABI");
        auto *P=dyn_cast<CallInst>(C.getArgOperand(4));
        if (!P || !namedCall(*P,"encbound_span_prepare") || P->arg_size()!=1 ||
            P->getArgOperand(0)!=C.getArgOperand(3) || !DT.dominates(P,&C))
            fail(F,C,"guarded span missing dominating matching token");
        // Proof mode verifies every scalar consumer through its bounded raw tree.
        if (!(LocalProofsOption && checkedProofRoot(&C))) {
        // No PHI/memory intrinsic/volatile access is admitted in this mode.
        auto *IP=dyn_cast<IntToPtrInst>(*C.user_begin());
        auto *Access=IP && IP->hasOneUse() ? dyn_cast<Instruction>(*IP->user_begin()) : nullptr;
        if (!Access || !(isa<LoadInst>(Access)||isa<StoreInst>(Access)) || spanBarrier(*Access) ||
            C.getParent()!=Access->getParent()) fail(F,C,"invalid span access");
        if (!DT.dominates(&C,Access)) fail(F,C,"span access precedes check");
        for (auto It=std::next(C.getIterator()); &*It!=Access; ++It)
            if (spanBarrier(*It)) fail(F,C,"barrier before span access");
        }
        if (P->getParent()==C.getParent()) {
            for (auto It=std::next(P->getIterator()); &*It!=&C; ++It)
                if (spanBarrier(*It)) fail(F,C,"barrier within span block");
            return;
        }
        for (Loop *L=LI.getLoopFor(C.getParent()); L; L=L->getParentLoop()) {
            if (L->getLoopPreheader()!=P->getParent()) continue;
            for (auto It=std::next(P->getIterator()); It!=P->getParent()->end(); ++It)
                if (spanBarrier(*It)) fail(F,C,"barrier after span preparation");
            for (BasicBlock *B : L->blocks())
                for (Instruction &I : *B)
                    if (spanBarrier(I)) fail(F,C,"barrier within span loop");
            return;
        }
        fail(F,C,"span token crosses unverified control flow");
    }

    // A checked address is `inttoptr(call @encbound_require(bytes, width, kind))`
    // whose decoded value does not escape, followed on the nonzero path by the
    // required check. Plain loads/stores use the direct form; a memory intrinsic
    // with a dynamic length uses a guarded PHI whose checked incoming edge is the
    // direct form.
    static void checkAccess(Function &F, Instruction &I, Value *addr,
                            uint64_t bytes, unsigned kind, DominatorTree &DT,
                            bool allowPhi) {
        if (LocalProofsOption && provenAddress(addr,&I)) return;
        if (isa<PHINode>(addr)) {
            if (!allowPhi) {
                fail(F, I, "load/store address is not a direct check");
            }
            return;
        }
        Value *expected =
            ConstantInt::get(Type::getInt64Ty(I.getContext()), bytes);
        CallInst *CI = nullptr;
        if (!extractCheck(addr, expected, kind, &I, &CI)) {
            fail(F, I, "nonzero access without a matching checked address");
        }
        if (!DT.dominates(CI, &I)) {
            fail(F, I, "required check does not dominate the access");
        }
    }

    // Memory-intrinsic length is a runtime value; the checked address must use
    // that exact length and kind. The dynamic-length form is a two-input PHI:
    // the checked incoming edge is the decoded address, and every other incoming
    // edge must be taken only when the length is zero. Prove that per edge; an
    // unrelated guard or an extra unchecked input fails closed.
    static void checkAccessLen(Function &F, Instruction &I, Value *addr,
                               Value *len, unsigned kind, DominatorTree &DT) {
        if (auto *PN = dyn_cast<PHINode>(addr)) {
            if (!checkGuardedPhi(F, I, PN, len, kind, DT)) {
                fail(F, I, "memory intrinsic has no checked nonzero path");
            }
            return;
        }
        // A direct decode is emitted only for a constant nonzero length.
        // Dynamic lengths must use the diamond, including when the runtime
        // value is zero; an unconditional require changes no-op semantics.
        if (!isa<ConstantInt>(len))
            fail(F, I, "dynamic memory intrinsic requires a zero guard");
        CallInst *CI = nullptr;
        if (!extractCheck(addr, len, kind, &I, &CI)) {
            fail(F, I, "memory intrinsic without a matching checked address");
        }
        if (!DT.dominates(CI, &I)) {
            fail(F, I, "required check does not dominate the intrinsic");
        }
    }

    // Validate the guarded intrinsic PHI edge by edge: the checked edge carries
    // the decoded address and its require call dominates the access; every other
    // edge must branch here only when `len` is zero.
    static bool checkGuardedPhi(Function &F, Instruction &I, PHINode *PN,
                                Value *len, unsigned kind, DominatorTree &DT) {
        if (PN->getNumIncomingValues() != 2 || PN->getParent() != I.getParent()) {
            return false;
        }
        BasicBlock *checkedPred = nullptr;
        BasicBlock *zeroPred = nullptr;
        for (unsigned idx = 0; idx < PN->getNumIncomingValues(); ++idx) {
            Value *Incoming = PN->getIncomingValue(idx);
            BasicBlock *Pred = PN->getIncomingBlock(idx);
            CallInst *CI = nullptr;
            if (extractCheck(Incoming, len, kind, &I, &CI)) {
                // The require must execute on the checked edge: it dominates
                // the predecessor's terminator (the PHI merges, so it need not
                // dominate the access block globally).
                if (checkedPred || CI == nullptr || CI->getParent() != Pred ||
                    !DT.dominates(CI, Pred->getTerminator())) {
                    return false;
                }
                checkedPred = Pred;
                continue;
            }
            if (zeroPred || !edgeIsZeroLengthGuard(Pred, PN->getParent(), len)) {
                return false;
            }
            zeroPred = Pred;
        }
        // Exactly the emitted diamond: the nonzero arm executes the checks,
        // and its only predecessor is the zero guard. This also ensures no
        // address is decoded on the zero-length path.
        if (!checkedPred || !zeroPred || checkedPred == zeroPred ||
            checkedPred->getSinglePredecessor() != zeroPred) {
            return false;
        }
        auto *CheckBR = dyn_cast<BranchInst>(checkedPred->getTerminator());
        auto *GuardBR = cast<BranchInst>(zeroPred->getTerminator());
        return CheckBR && CheckBR->isUnconditional() &&
               CheckBR->getSuccessor(0) == PN->getParent() &&
               (GuardBR->getSuccessor(0) == checkedPred ||
                GuardBR->getSuccessor(1) == checkedPred);
    }

    // True only if the edge Pred -> Succ can be taken only when `len` is zero.
    // Accepts the instrumenter's `%c = icmp eq/ne len, 0` conditional branch and
    // requires the edge to be the zero side. Anything else fails closed.
    static bool edgeIsZeroLengthGuard(BasicBlock *Pred, BasicBlock *Succ,
                                      Value *len) {
        auto *BR = dyn_cast<BranchInst>(Pred->getTerminator());
        if (BR == nullptr || !BR->isConditional() ||
            BR->getSuccessor(0) == BR->getSuccessor(1)) {
            return false;
        }
        auto *Cmp = dyn_cast<ICmpInst>(BR->getCondition());
        if (Cmp == nullptr) {
            return false;
        }
        Value *ZeroCandidate = nullptr;
        if (Cmp->getOperand(0) == len) {
            ZeroCandidate = Cmp->getOperand(1);
        } else if (Cmp->getOperand(1) == len) {
            ZeroCandidate = Cmp->getOperand(0);
        }
        if (ZeroCandidate == nullptr) {
            return false;
        }
        auto *Zero = dyn_cast<ConstantInt>(ZeroCandidate);
        if (Zero == nullptr || !Zero->isZero()) {
            return false;
        }
        if (Cmp->getPredicate() == CmpInst::ICMP_EQ) {
            return BR->getSuccessor(0) == Succ;
        }
        if (Cmp->getPredicate() == CmpInst::ICMP_NE) {
            return BR->getSuccessor(1) == Succ;
        }
        return false;
    }

    // Confirm `v` is a decoded checked address for `width`/`kind` and confine the
    // decoded raw pointer to the access (directly, or through the guarded
    // intrinsic PHI). Returns the require call in *out when the direct form holds.
    static bool extractCheck(Value *v, Value *width, unsigned kind,
                             Instruction *access, CallInst **out) {
        auto *IP = dyn_cast<IntToPtrInst>(v);
        if (IP == nullptr) {
            return false;
        }
        auto *CI = dyn_cast<CallInst>(IP->getOperand(0));
        if (CI == nullptr) {
            return false;
        }
        Function *Callee = CI->getCalledFunction();
        if (Callee == nullptr || (Callee->getName() != "encbound_require" &&
                                  Callee->getName() != "encbound_span_require")) {
            return false;
        }
        // The raw integer result may be decoded exactly once, by IP. A second
        // use (return, store, another cast) is an escape of the raw address.
        if (!CI->hasOneUse() || CI->arg_size() !=
                (Callee->getName() == "encbound_span_require" ? 5u : 3u) ||
            !CI->getType()->isIntegerTy(64)) {
            return false;
        }
        if (!widthMatches(CI->getArgOperand(1), width)) {
            return false;
        }
        auto *K = dyn_cast<ConstantInt>(CI->getArgOperand(2));
        if (K == nullptr || K->getZExtValue() != kind) {
            return false;
        }
        if (access != nullptr && !decodedConfined(IP, *access)) {
            return false;
        }
        if (out != nullptr) {
            *out = CI;
        }
        return true;
    }

    // The decoded raw pointer may be used only by the access it was decoded for,
    // or by a PHI that feeds that access and nothing else (the guarded intrinsic
    // form). Any other use of the decoded pointer or of that PHI is an escape.
    static bool decodedConfined(IntToPtrInst *IP, Instruction &I) {
        if (!IP->hasOneUse()) {
            return false;
        }
        Use *U = &*IP->use_begin();
        if (auto *PN = dyn_cast<PHINode>(U->getUser())) {
            if (!PN->hasOneUse()) return false;
            U = &*PN->use_begin();
        }
        return U->getUser() == &I && isAddressUse(*U);
    }

    static bool isAddressUse(const Use &U) {
        if (isa<AtomicRMWInst>(U.getUser()) || isa<AtomicCmpXchgInst>(U.getUser()))
            return U.getOperandNo()==0;
        if (auto *LI = dyn_cast<LoadInst>(U.getUser()))
            return U.getOperandNo() == LI->getPointerOperandIndex();
        if (auto *SI = dyn_cast<StoreInst>(U.getUser()))
            return U.getOperandNo() == SI->getPointerOperandIndex();
        if (auto *II = dyn_cast<IntrinsicInst>(U.getUser())) {
            unsigned id = II->getIntrinsicID();
            if (id == Intrinsic::memset) return U.getOperandNo() == 0;
            if (id == Intrinsic::memcpy || id == Intrinsic::memmove)
                return U.getOperandNo() < 2;
        }
        return false;
    }

    // Inspect every raw-producing call, including orphan decodes that no
    // memory-access scan would visit. Exactly one decode and one address use
    // (optionally through the emitted PHI) are permitted.
    static void verifyRawResult(Function &F, CallInst &CI) {
        if (LocalProofsOption && checkedProofRoot(&CI)) return;
        if (!CI.hasOneUse()) fail(F, CI, "raw result must have one decode");
        auto *IP = dyn_cast<IntToPtrInst>(*CI.user_begin());
        if (!IP || !IP->hasOneUse())
            fail(F, CI, "raw result escapes its address decode");
        User *U = *IP->user_begin();
        if (auto *PN = dyn_cast<PHINode>(U)) {
            if (!PN->hasOneUse()) fail(F, CI, "decoded PHI escapes");
            U = *PN->user_begin();
        }
        auto *Access = dyn_cast<Instruction>(U);
        if (!Access || !decodedConfined(IP, *Access))
            fail(F, CI, "decoded result escapes its address operand");
        if (auto *II = dyn_cast<IntrinsicInst>(Access)) {
            // Account for this producer even when it enters the PHI's zero
            // arm: an unrelated-width decode there must not be mistaken for
            // an ordinary encoded operand by the per-access check.
            Use *Address = &*IP->use_begin();
            if (auto *PN = dyn_cast<PHINode>(Address->getUser()))
                Address = &*PN->use_begin();
            unsigned Kind = Address->getOperandNo() == 0 ? kAccessWrite : kAccessRead;
            if (!extractCheck(IP, II->getArgOperand(2), Kind, Access, nullptr))
                fail(F, CI, "raw intrinsic result does not match its access");
            if (auto *Len = dyn_cast<ConstantInt>(II->getArgOperand(2))) {
                if (Len->isZero()) fail(F, CI, "zero-length access decodes an address");
            }
        }
    }

    // The post-transform module must carry none of the policy attributes the
    // sanitizer removes: a surviving promise could be paired with an encoded
    // pointer. Intrinsic declarations are checked against LLVM's mandatory
    // contract separately; explicit call-site promises are checked here.
    static void verifySanitizedSignature(Function &F) {
        if (F.isVarArg() && (!F.isDeclaration() || !F.use_empty()) &&
            !(CxxEHOption && F.getName()=="encbound_eh_personality"))
            failFn(F, "native variadic ABI survived the transform");
        for (Attribute::AttrKind K : kFnAttrKinds) {
            if (F.hasFnAttribute(K)) {
                failFn(F, "function promise survived the transform");
            }
        }
        for (Attribute::AttrKind K : kPtrAttrKinds) {
            if (F.hasRetAttribute(K)) {
                failFn(F, "return pointer promise survived the transform");
            }
            for (unsigned i = 0; i < F.arg_size(); ++i) {
                if (F.hasParamAttribute(i, K)) {
                    failFn(F, "parameter pointer promise survived the transform");
                }
            }
        }
        for (Attribute::AttrKind K : kAbiAttrKinds) {
            for (unsigned i = 0; i < F.arg_size(); ++i) {
                if (F.hasParamAttribute(i, K))
                    failFn(F, "implicit-memory ABI survived on signature");
            }
        }
        for (Instruction &I : instructions(F)) {
            auto *CB = dyn_cast<CallBase>(&I);
            if (CB == nullptr) {
                continue;
            }
            if (CB->getFunctionType()->isVarArg())
                fail(F, I, "native variadic call survived the transform");
            for (Attribute::AttrKind K : kFnAttrKinds) {
                if (CB->getAttributes().hasFnAttr(K)) {
                    fail(F, I,
                         "call-site function promise survived the transform");
                }
            }
            for (Attribute::AttrKind K : kPtrAttrKinds) {
                if (CB->getAttributes().hasRetAttr(K)) {
                    fail(F, I,
                         "call-site return promise survived the transform");
                }
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    // Inspect explicit call-site attributes; do not conflate
                    // them with mandatory attributes on intrinsic declarations.
                    if (CB->getAttributes().hasParamAttr(i, K)) {
                        fail(F, I,
                             "call-site parameter promise survived the transform");
                    }
                }
            }
            for (Attribute::AttrKind K : kAbiAttrKinds) {
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    if (CB->paramHasAttr(i, K)) {
                        fail(F, I, "implicit-memory ABI survived the transform");
                    }
                }
            }
        }
    }

    static bool widthMatches(Value *actual, Value *expected) {
        if (actual == expected) {
            return true;
        }
        auto *A = dyn_cast<ConstantInt>(actual);
        auto *E = dyn_cast<ConstantInt>(expected);
        return A != nullptr && E != nullptr &&
            A->getValue().getActiveBits() <= 64 && E->getValue().getActiveBits() <= 64 &&
            A->getValue().zextOrTrunc(64) == E->getValue().zextOrTrunc(64);
    }

    [[noreturn]] static void fail(Function &F, Instruction &I, const char *why) {
        std::string msg;
        raw_string_ostream os(msg);
        os << "ENCBound: validation failed (" << why << ") in " << F.getName()
           << ": " << I;
        report_fatal_error(Twine(os.str()));
    }

    [[noreturn]] static void failFn(Function &F, const char *why) {
        std::string msg;
        raw_string_ostream os(msg);
        os << "ENCBound: validation failed (" << why << ") in " << F.getName();
        report_fatal_error(Twine(os.str()));
    }
};

#include "encbound_fast_paths.h"

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "ENCBoundPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                if (const char *Early=std::getenv("ENCBOUND_VLA_FRONTEND"); Early && StringRef(Early)=="1")
                    PB.registerPipelineStartEPCallback(
                        [](ModulePassManager &MPM, OptimizationLevel) {
                            MPM.addPass(dynamic_stack::SizingPass());
                        });
                PB.registerPipelineParsingCallback(
                    [](StringRef name, ModulePassManager &MPM,
                       ArrayRef<PassBuilder::PipelineElement>) {
                        if (name == "encbound-vla-sizing") { MPM.addPass(dynamic_stack::SizingPass()); return true; }
                        if (name == "encbound-cxx-baseline") { MPM.addPass(ENCBoundCxxBaselinePass()); return true; }
                        if (name == "encbound-variadic-baseline") { MPM.addPass(ENCBoundVariadicBaselinePass()); return true; }
                        if (name == "encbound-fast") { MPM.addPass(ENCBoundFastPass()); return true; }
                        if (name == "encbound-fast-verify") { MPM.addPass(ENCBoundFastVerifyPass()); return true; }
                        if (name == "encbound") {
                            MPM.addPass(ENCBoundPass());
                            return true;
                        }
                        if (name == "encbound-local-proofs") {
                            MPM.addPass(ENCBoundLocalProofPass());
                            return true;
                        }
                        if (name == "encbound-reuse") {
                            MPM.addPass(ENCBoundReusePass());
                            return true;
                        }
                        if (name == "encbound-verify") {
                            MPM.addPass(ENCBoundVerifyPass());
                            return true;
                        }
                        if (name == "encbound-post-instcombine") {
                            MPM.addPass(ENCBoundPostInstCombinePass());
                            return true;
                        }
                        return false;
                    });
            }};
}
