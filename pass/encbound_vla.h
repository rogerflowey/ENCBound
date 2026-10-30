// Owner-authorized dynamic stack protocol (docs/legacy/steps/20-vla.md).
// Included in the compiler's anonymous namespace after shared call predicates.
namespace dynamic_stack {
[[noreturn]] inline void reject(const Function &F, StringRef Why) {
    report_fatal_error(Twine("ENCBound: unsupported VLA protocol in ") +
                       F.getName() + ": " + Why);
}
inline bool intrinsic(const Value *V, Intrinsic::ID ID) {
    auto *I = dyn_cast<IntrinsicInst>(V);
    return I && I->getIntrinsicID() == ID;
}
inline bool privateToken(const Value *V, unsigned Depth=0) {
    if (Depth>32) return false;
    if (intrinsic(V,Intrinsic::stacksave)) return true;
    auto *P=dyn_cast<PHINode>(V);
    if (!P || P->getNumIncomingValues()==0) return false;
    for (Value *Incoming:P->incoming_values())
        if (!privateToken(Incoming,Depth+1)) return false;
    return true;
}
inline bool tokenUsers(const Value *V, bool Output, unsigned Depth=0) {
    if (Depth>32) return false;
    for (const User *U:V->users()) {
        if (intrinsic(U,Intrinsic::stackrestore)) continue;
        if (auto *P=dyn_cast<PHINode>(U)) {
            if (privateToken(P) && tokenUsers(P,Output,Depth+1)) continue;
        }
        auto *C=dyn_cast<CallInst>(U);
        if (Output && C && namedCall(*C,"encbound_stack_prepare") &&
            C->arg_size()==4 && C->getArgOperand(0)==V) continue;
        return false;
    }
    return true;
}
// Clang -O0 spills raw save tokens. Promote ONLY nonescaping, canonical save
// cells; arbitrary application memory must never control machine stack state.
inline void normalize(Function &F) {
    if (!VLAOption) return;
    SmallVector<AllocaInst *, 8> Cells;
    for (Instruction &I : instructions(F)) {
        if (!intrinsic(&I, Intrinsic::stacksave)) continue;
        for (User *U : I.users()) {
            auto *S = dyn_cast<StoreInst>(U);
            if (!S) continue;
            auto *A = dyn_cast<AllocaInst>(S->getPointerOperand());
            if (S->getValueOperand() != &I || !A || !A->isStaticAlloca() ||
                !isAllocaPromotable(A)) reject(F, "escaping stack-save cell");
            if (!is_contained(Cells, A)) Cells.push_back(A);
        }
    }
    for (AllocaInst *A : Cells)
        for (User *U : A->users())
            if (auto *S = dyn_cast<StoreInst>(U))
                if (!intrinsic(S->getValueOperand(), Intrinsic::stacksave))
                    reject(F, "application-written stack-save cell");
    if (!Cells.empty()) {
        DominatorTree DT(F);
        PromoteMemToReg(Cells, DT);
    }
    for (Instruction &I : instructions(F)) {
        if (intrinsic(&I, Intrinsic::stacksave)) {
            if (!tokenUsers(&I,false)) reject(F, "raw stack-save token escapes");
        } else if (intrinsic(&I, Intrinsic::stackrestore)) {
            if (!privateToken(cast<CallInst>(I).getArgOperand(0)))
                reject(F, "restore requires a private save token");
        }
    }
}

// Preserve the original integer width and signed overflow contract. A failed
// product becomes zero, which propagates through the product/cast tree and is
// rejected by prepare before moving SP. No runtime call or authority is needed
// for this value-only normalization.
inline Value *checkedSize(IRBuilder<> &B, Value *V, unsigned Depth=0) {
    auto *T=dyn_cast<IntegerType>(V->getType());
    if (!T || T->getBitWidth()>64 || Depth>32)
        reject(*B.GetInsertBlock()->getParent(),"dimension type/depth");
    if (auto *Cast=dyn_cast<CastInst>(V)) {
        if (Cast->getOpcode()==Instruction::ZExt || Cast->getOpcode()==Instruction::SExt) {
            Value *Input=checkedSize(B,Cast->getOperand(0),Depth+1);
            return B.CreateCast(Cast->getOpcode(),Input,T,"encbound.vla.extent");
        }
    }
    auto *Op=dyn_cast<BinaryOperator>(V);
    if (!Op || (Op->getOpcode()!=Instruction::Mul && Op->getOpcode()!=Instruction::Shl))
        return V;
    Value *Left=checkedSize(B,Op->getOperand(0),Depth+1);
    Value *Result=nullptr, *Overflow=nullptr;
    bool Signed=Op->hasNoSignedWrap() && !Op->hasNoUnsignedWrap();
    if (Op->getOpcode()==Instruction::Mul) {
        Value *Right=checkedSize(B,Op->getOperand(1),Depth+1);
        auto ID=Signed ? Intrinsic::smul_with_overflow : Intrinsic::umul_with_overflow;
        auto *Fn=Intrinsic::getOrInsertDeclaration(B.GetInsertBlock()->getModule(),ID,{T});
        Value *Product=B.CreateCall(Fn,{Left,Right},"encbound.vla.product");
        Result=B.CreateExtractValue(Product,0);
        Overflow=B.CreateExtractValue(Product,1);
    } else {
        auto *K=dyn_cast<ConstantInt>(Op->getOperand(1));
        if (!K || K->getZExtValue()>=T->getBitWidth())
            reject(*Op->getFunction(),"dimension shift");
        Result=B.CreateShl(Left,K,"encbound.vla.shift");
        Value *Restored=Signed ? B.CreateAShr(Result,K) : B.CreateLShr(Result,K);
        Overflow=B.CreateICmpNE(Restored,Left);
    }
    return B.CreateSelect(Overflow,ConstantInt::get(T,0),Result,"encbound.vla.extent");
}

// Run before frontend optimization: reassociation/CSE can remove nsw/nuw and
// make signed source products indistinguishable from unsigned VLA dimensions.
// Promote only nonescaping scalar cells on a sizing path, so `n = x*y; a[n]`
// receives the same arithmetic checks as `a[x*y]`, including at frontend O0.
inline void sizingCells(Value *V, SmallVectorImpl<AllocaInst *> &Cells,
                        SmallPtrSetImpl<Value *> &Seen) {
    if (!Seen.insert(V).second) return;
    if (auto *L=dyn_cast<LoadInst>(V)) {
        auto *A=dyn_cast<AllocaInst>(L->getPointerOperand());
        if (A && A->isStaticAlloca() && A->getAllocatedType()->isIntegerTy() &&
            isAllocaPromotable(A) && !is_contained(Cells,A)) Cells.push_back(A);
    } else if (auto *I=dyn_cast<Instruction>(V)) {
        if (I->getOpcode()==Instruction::Mul || I->getOpcode()==Instruction::Shl ||
            I->getOpcode()==Instruction::ZExt || I->getOpcode()==Instruction::SExt)
            for (Value *Operand:I->operands()) sizingCells(Operand,Cells,Seen);
    }
}
inline bool sizedBeforeOptimization(Module &M) {
    auto *Flag=M.getModuleFlag("encbound.vla.sizing");
    if (!Flag) return false;
    auto *Version=mdconst::dyn_extract<ConstantInt>(Flag);
    if (!Version || !Version->equalsInt(1))
        report_fatal_error("ENCBound: unsupported VLA sizing version");
    return true;
}
struct SizingPass : PassInfoMixin<SizingPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        if (sizedBeforeOptimization(M)) return PreservedAnalyses::all();
        for (Function &F:M) {
            SmallVector<AllocaInst *,8> Dynamic;
            for (Instruction &I:instructions(F))
                if (auto *A=dyn_cast<AllocaInst>(&I); A && !A->isStaticAlloca())
                    Dynamic.push_back(A);
            if (Dynamic.empty()) continue;
            for (unsigned Round=0;;++Round) {
                SmallVector<AllocaInst *,8> Cells;
                SmallPtrSet<Value *,32> Seen;
                for (AllocaInst *A:Dynamic) sizingCells(A->getArraySize(),Cells,Seen);
                if (Cells.empty()) break;
                if (Round>32) reject(F,"dimension cell depth");
                DominatorTree DT(F);
                PromoteMemToReg(Cells,DT);
            }
            for (AllocaInst *A:Dynamic) {
                IRBuilder<> B(A);
                A->setOperand(0,checkedSize(B,A->getArraySize()));
            }
        }
        M.addModuleFlag(Module::Error,"encbound.vla.sizing",1);
        return PreservedAnalyses::none();
    }
    static bool isRequired() { return true; }
};

// Standalone opt input still gets checked sizing. A caller optimizing IR first
// must run encbound-vla-sizing before that optimization to preserve signedness.
inline Value *checkedCount(IRBuilder<> &B, Value *V, unsigned Depth=0) {
    auto *I64=B.getInt64Ty();
    Value *Checked=checkedSize(B,V,Depth);
    if (Checked!=V) {
        auto Product=B.GetInsertBlock()->getModule()->getOrInsertFunction(
            "encbound_stack_product",FunctionType::get(I64,{I64,I64},false));
        return B.CreateCall(Product,{B.CreateZExtOrTrunc(Checked,I64),B.getInt64(1)},
                            "encbound.vla.count");
    }
    return B.CreateZExtOrTrunc(V,I64);
}
inline void rewrite(Module &M, AllocaInst &A) {
    const DataLayout &DL = M.getDataLayout();
    auto *CountTy = dyn_cast<IntegerType>(A.getArraySize()->getType());
    uint64_t Element = DL.getTypeAllocSize(A.getAllocatedType());
    if (!CountTy || CountTy->getBitWidth() > 64 || !Element ||
        Element > (1ull << 30) || A.isUsedWithInAlloca() || A.isSwiftError())
        reject(*A.getFunction(), "allocation type/size/ABI");
    auto &C = M.getContext();
    auto *I64 = Type::getInt64Ty(C);
    auto *P = PointerType::get(C, 0);
    auto Prepare = M.getOrInsertFunction("encbound_stack_prepare",
        FunctionType::get(I64, {P,I64,I64,I64}, false));
    auto Mint = M.getOrInsertFunction("encbound_stack_mint_dynamic",
        FunctionType::get(I64, {P,I64}, false));
    IRBuilder<> B(&A);
    Value *Count = sizedBeforeOptimization(M) ? B.CreateZExtOrTrunc(A.getArraySize(),I64) :
                                              checkedCount(B,A.getArraySize());
    auto *Save = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::stacksave, {P});
    Value *SP = B.CreateCall(Save, {}, "encbound.vla.sp");
    Value *Slot = B.CreateCall(Prepare, {SP, Count, B.getInt64(Element),
                               B.getInt64(A.getAlign().value())}, "encbound.vla.size");
    Value *Reserve = B.CreateShl(Slot, 1, "encbound.vla.reserve");
    auto *Raw = B.CreateAlloca(B.getInt8Ty(), Reserve, "encbound.vla.storage");
    Raw->setAlignment(Align(16));
    Value *Cap = B.CreateCall(Mint, {Raw, Slot}, "encbound.vla.cap");
    A.replaceAllUsesWith(B.CreateIntToPtr(Cap, P, "encbound.vla.object"));
    A.eraseFromParent();
}

// Structural output check: names/metadata are not proof of a reservation.
inline bool reservation(AllocaInst &A) {
    if (!VLAOption || !A.getAllocatedType()->isIntegerTy(8) ||
        A.getAddressSpace() != 0 || A.getAlign() != Align(16) ||
        A.isUsedWithInAlloca() || A.isSwiftError() || !A.hasOneUse()) return false;
    auto *Double = dyn_cast<BinaryOperator>(A.getArraySize());
    if (!Double || Double->getOpcode() != Instruction::Shl ||
        !Double->getType()->isIntegerTy(64) || !Double->hasOneUse() ||
        !isa<ConstantInt>(Double->getOperand(1)) ||
        !cast<ConstantInt>(Double->getOperand(1))->isOne() ||
        Double->hasNoUnsignedWrap() || Double->hasNoSignedWrap()) return false;
    auto *Prepare = dyn_cast<CallInst>(Double->getOperand(0));
    auto *Mint = dyn_cast<CallInst>(*A.user_begin());
    if (!Prepare || !Mint || !namedCall(*Prepare,"encbound_stack_prepare") ||
        !namedCall(*Mint,"encbound_stack_mint_dynamic") ||
        Prepare->arg_size()!=4 || Mint->arg_size()!=2 ||
        Mint->getArgOperand(0)!=&A || Mint->getArgOperand(1)!=Prepare ||
        Prepare->getNumUses()!=2) return false;
    auto &C=A.getContext(); auto *I64=Type::getInt64Ty(C); auto *P=PointerType::get(C,0);
    if (Prepare->getFunctionType()!=FunctionType::get(I64,{P,I64,I64,I64},false) ||
        Mint->getFunctionType()!=FunctionType::get(I64,{P,I64},false) ||
        Prepare->getCallingConv()!=CallingConv::C || Mint->getCallingConv()!=CallingConv::C ||
        Prepare->hasOperandBundles() || Mint->hasOperandBundles()) return false;
    auto *SP=dyn_cast<IntrinsicInst>(Prepare->getArgOperand(0));
    auto *Element=dyn_cast<ConstantInt>(Prepare->getArgOperand(2));
    auto *Alignment=dyn_cast<ConstantInt>(Prepare->getArgOperand(3));
    return SP && SP->getIntrinsicID()==Intrinsic::stacksave && SP->hasOneUse() &&
        Element && Element->getZExtValue()>0 && Element->getZExtValue()<=(1ull<<30) &&
        Alignment && isPowerOf2_64(Alignment->getZExtValue()) &&
        Alignment->getZExtValue()<=(1ull<<30) &&
        SP->getNextNonDebugInstruction()==Prepare &&
        Prepare->getNextNonDebugInstruction()==Double &&
        Double->getNextNonDebugInstruction()==&A && A.getNextNonDebugInstruction()==Mint;
}

inline void verify(Function &F) {
    auto Fail=[&](StringRef Why) {
        report_fatal_error(Twine("ENCBound: validation failed: dynamic stack in ")+
                           F.getName()+": "+Why);
    };
    for (Instruction &I : instructions(F)) {
        if (namedCall(I,"encbound_stack_product")) {
            auto *C=cast<CallInst>(&I);auto *I64=Type::getInt64Ty(F.getContext());
            if (!VLAOption || C->getFunctionType()!=FunctionType::get(I64,{I64,I64},false) ||
                C->getCallingConv()!=CallingConv::C || C->hasOperandBundles() || C->use_empty())
                Fail("invalid dimension product");
            for (User *U:C->users()) {
                auto *Next=dyn_cast<CallInst>(U);
                if (!Next || !(namedCall(*Next,"encbound_stack_product") ||
                    (namedCall(*Next,"encbound_stack_prepare") && Next->arg_size()==4 &&
                     Next->getArgOperand(1)==C))) Fail("dimension product escapes");
            }
        }
        if (auto *A=dyn_cast<AllocaInst>(&I))
            if (!A->isStaticAlloca() && !reservation(*A)) Fail("invalid reservation");
        if (namedCall(I,"encbound_stack_mint_dynamic")) {
            auto *C=cast<CallInst>(&I);
            auto *A=C->arg_size()==2 ? dyn_cast<AllocaInst>(C->getArgOperand(0)) : nullptr;
            if (!A || !reservation(*A)) Fail("invalid dynamic mint");
        }
        if (namedCall(I,"encbound_stack_prepare")) {
            bool Found=false;
            for (User *U:I.users()) if (auto *B=dyn_cast<BinaryOperator>(U))
                for (User *V:B->users()) if (auto *A=dyn_cast<AllocaInst>(V))
                    Found |= reservation(*A);
            if (!Found) Fail("orphan preflight");
        }
        if (intrinsic(&I,Intrinsic::stacksave)) {
            if (!VLAOption) Fail("stack save without VLA admission");
            if (!tokenUsers(&I,true)) Fail("raw save token escapes");
        } else if (intrinsic(&I,Intrinsic::stackrestore)) {
            if (!VLAOption || !privateToken(cast<CallInst>(I).getArgOperand(0)))
                Fail("untrusted restore token");
        }
    }
}
} // namespace dynamic_stack
