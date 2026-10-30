// Application-only ownership/admission around the pinned LLVM expander.
cl::opt<bool> VariadicsOption("encbound-variadics", cl::init(false), cl::Hidden);

bool variadicScalar(Type *T) {
    return T->isDoubleTy() || (T->isIntegerTy() && T->getIntegerBitWidth() <= 64) ||
        (T->isPointerTy() && T->getPointerAddressSpace() == 0);
}
void validateVariadicSignature(FunctionType *T, AttributeList A, unsigned CC,
                               unsigned Arguments) {
    if (CC != CallingConv::C || !(T->getReturnType()->isVoidTy() || variadicScalar(T->getReturnType())))
        report_fatal_error("ENCBound: unsupported variadic calling convention/result");
    for (Type *P : T->params()) if (!variadicScalar(P))
        report_fatal_error("ENCBound: unsupported variadic fixed parameter type");
    for (unsigned I = 0; I < Arguments; ++I) {
        for (auto K : kAbiAttrKinds) if (A.hasParamAttr(I, K))
            report_fatal_error("ENCBound: unsupported variadic implicit memory ABI");
        for (auto K : {Attribute::InReg, Attribute::Nest, Attribute::SwiftSelf,
                        Attribute::SwiftError})
            if (A.hasParamAttr(I, K))
                report_fatal_error("ENCBound: unsupported variadic parameter ABI attribute");
    }
    // `returned` is an equality promise, not an argument-passing convention.
    // Fixed arguments and their returned bits are unchanged by frame packing;
    // the LLVM expander preserves the attribute on those original parameters.
}

void normalizeVariadicABI(Module &M, SmallPtrSetImpl<Function *> &Private) {
    if (!VariadicsOption) return;
    const Triple &T = M.getTargetTriple();
    if (T.getArch() != Triple::x86_64 || !T.isOSLinux() ||
        M.getDataLayout().getPointerSizeInBits() != 64 ||
        !M.getDataLayout().isLittleEndian())
        report_fatal_error("ENCBound: variadics require x86-64 Linux SysV");
    StringRef Profile = ProfileOption.empty() ? StringRef("unknown") : StringRef(ProfileOption);
    if (Profile != "BASELINE" && Profile != "RADIX_ONLY" && Profile != "MAC27")
        report_fatal_error("ENCBound: variadics require an explicit protection profile");
    SmallVector<Function *, 16> Work, Unused;
    DenseMap<Function *, std::string> Signatures;
    SmallPtrSet<Function *, 16> AddressTaken;
    std::string Records;
    for (Function &F : M) {
        if (F.getName().starts_with("__encbound_va_"))
            report_fatal_error("ENCBound: unsupported source private variadic ABI symbol");
        if (!F.isVarArg() || F.isIntrinsic()) continue;
        if (CxxEHOption && (F.getName()=="encbound_eh_personality" ||
            (ProfileOption=="BASELINE" && F.getName()=="__gxx_personality_v0"))) continue;
        if (F.isDeclaration() && F.use_empty()) { Unused.push_back(&F); continue; }
        if (F.isDeclaration() && (!admittedInventory().admitted.contains(F.getName()) ||
            admittedInventory().redirect.contains(F.getName())))
            report_fatal_error(Twine("ENCBound: unowned variadic declaration: ") + F.getName());
        if (F.hasFnAttribute(Attribute::Naked))
            report_fatal_error("ENCBound: unsupported naked variadic function");
        validateVariadicSignature(F.getFunctionType(), F.getAttributes(), F.getCallingConv(), F.arg_size());
        // Code pointers retain their bits. LLVM's Lowering mode replaces every
        // use (including table initializers) with the fixed-arity entry. All
        // application callers must use that same private ABI; this is not CFI.
        for (Use &U : F.uses()) {
            auto *C = dyn_cast<CallBase>(U.getUser());
            if (C && C->isCallee(&U)) {
                if (C->getFunctionType() != F.getFunctionType())
                    report_fatal_error("ENCBound: unsupported variadic call/ownership/prototype");
            } else {
                if (!CallbacksOption)
                    report_fatal_error("ENCBound: variadic function address requires callbacks");
                // Aliases have their own declared FunctionType. Replacing only
                // the aliasee would leave the original variadic alias ABI.
                if (isa<GlobalAlias>(U.getUser()))
                    report_fatal_error("ENCBound: unsupported variadic function alias");
                AddressTaken.insert(&F);
            }
        }
        Signatures[&F] = "encbound-va-v1:" + Profile.str() + ":" +
            aggregateSignature(F.getFunctionType(), F.getAttributes(), F.getCallingConv());
        Work.push_back(&F);
    }
    // Validate every original call before the upstream code erases attributes
    // or changes the function's signature. No native or unknown fallback.
    for (Function &F : M) for (Instruction &I : instructions(F)) {
        if (isa<VAArgInst>(I))
            report_fatal_error("ENCBound: unsupported residual LLVM va_arg instruction");
        auto *C = dyn_cast<CallBase>(&I);
        if (!C || !C->getFunctionType()->isVarArg() || isa<IntrinsicInst>(C)) continue;
        auto *Target = C->getCalledFunction();
        if ((!isa<CallInst>(C) && !(CxxEHOption && isa<InvokeInst>(C))) ||
            (Target && (!Signatures.count(Target) || C->getFunctionType() != Target->getFunctionType())) ||
            C->isMustTailCall() || C->hasOperandBundles())
            report_fatal_error("ENCBound: unsupported variadic call/ownership/prototype");
        if (!Target && !CallbacksOption)
            report_fatal_error("ENCBound: indirect variadic call requires callbacks");
        validateVariadicSignature(C->getFunctionType(), C->getAttributes(), C->getCallingConv(), C->arg_size());
        if (Target && aggregateSignature(C->getFunctionType(), C->getAttributes(), C->getCallingConv()) !=
            aggregateSignature(Target->getFunctionType(), Target->getAttributes(), Target->getCallingConv()))
            report_fatal_error("ENCBound: mismatched variadic ABI attributes");
        for (Value *A : C->args()) if (!variadicScalar(A->getType()))
            report_fatal_error("ENCBound: unsupported x86 variadic argument type");
        if (!Target)
            Records += "I encbound-va-v1:" + Profile.str() + ":" +
                aggregateSignature(C->getFunctionType(), C->getAttributes(), C->getCallingConv()) + "\n";
    }
    for (Function *F : Unused) F->eraseFromParent();
    for (Function *F : Work) {
        MD5 Hash; Hash.update(Signatures[F]); MD5::MD5Result Result; Hash.final(Result);
        SmallString<32> Hex; MD5::stringifyResult(Result, Hex);
        std::string Name = ("__encbound_va_" + Hex + "_" + F->getName()).str();
        if (M.getNamedValue(Name)) report_fatal_error("ENCBound: private variadic ABI collision");
        Records += (F->isDeclaration() ? "R " : "D ") + Name + " " + Signatures[F] + "\n";
        if (AddressTaken.contains(F)) Records += "A " + Name + " " + Signatures[F] + "\n";
        F->setName(Name);
        if (F->hasComdat()) F->setComdat(M.getOrInsertComdat(Name));
    }
    encbound_variadics::expand(M);
    for (Function &F : M) {
        if (F.getName().starts_with("__encbound_va_") && !F.isIntrinsic()) {
            if (F.isVarArg()) report_fatal_error("ENCBound: native variadic ABI survived expansion");
            Private.insert(&F);
        }
        for (Instruction &I : instructions(F)) {
            auto *Call = dyn_cast<CallBase>(&I);
            if (Call && !isa<IntrinsicInst>(Call) && Call->getFunctionType()->isVarArg())
                report_fatal_error("ENCBound: native variadic call survived expansion");
            auto *II = dyn_cast<IntrinsicInst>(&I);
            if (II && (II->getIntrinsicID() == Intrinsic::vastart ||
                II->getIntrinsicID() == Intrinsic::vacopy || II->getIntrinsicID() == Intrinsic::vaend))
                report_fatal_error("ENCBound: native va intrinsic survived expansion");
        }
    }
    if (!Records.empty()) {
        auto *Init = ConstantDataArray::getString(M.getContext(), Records, true);
        auto *G = new GlobalVariable(M, Init->getType(), true, GlobalValue::PrivateLinkage,
                                    Init, "__encbound_va_records");
        G->setSection(".encbound.abi"); G->setAlignment(Align(1)); appendToUsed(M, {G});
    }
}

struct ENCBoundVariadicBaselinePass : PassInfoMixin<ENCBoundVariadicBaselinePass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        SmallPtrSet<Function *, 16> Private;
        normalizeVariadicABI(M, Private);
        return VariadicsOption ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};
