// Included in the pass's anonymous namespace. Opt-in step 16 admission.
cl::opt<bool> CallbacksOption("encbound-callbacks", cl::init(false), cl::Hidden);
cl::opt<bool> CxxAllocationOption("encbound-cxx-allocations", cl::init(false), cl::Hidden);

cl::opt<bool> VirtualsOption("encbound-virtuals", cl::init(false), cl::Hidden);

// Resolve compiler-emitted aliases to same-module function definitions before
// service/aggregate rewriting. Preserve alias symbols for separate-unit users.
void validateFunctionAliases(Module &M) {
    for (GlobalAlias &A : M.aliases()) {
        auto *F = dyn_cast_or_null<Function>(A.getAliaseeObject());
        if (!VirtualsOption || !F || F->isDeclaration() || A.isInterposable() ||
            A.getValueType()!=F->getFunctionType() || A.getAddressSpace()!=0 ||
            A.getAliasee()!=F)
            report_fatal_error("ENCBound: unsupported function alias");
        for (unsigned I=0; I<F->arg_size(); ++I)
            if (F->hasParamAttribute(I,Attribute::ByVal) || F->hasParamAttribute(I,Attribute::StructRet))
                report_fatal_error("ENCBound: aggregate function alias requires private ABI mapping");
        A.replaceAllUsesWith(F);
    }
}

using ServiceMapping = std::pair<std::string, FunctionType *>;
ServiceMapping serviceMapping(Module &M, StringRef N) {
    auto &C = M.getContext();
    Type *P = PointerType::get(C, 0), *Z = Type::getInt64Ty(C);
    Type *I = Type::getInt32Ty(C), *V = Type::getVoidTy(C);
    auto Map = [&](StringRef Name, Type *R, std::initializer_list<Type *> Args) {
        return ServiceMapping{Name.str(), FunctionType::get(R, Args, false)};
    };
    if (CxxEHOption) {
        if (N == "__cxa_allocate_exception") return Map("encbound_eh_allocate_exception", P, {Z});
        if (N == "__cxa_free_exception") return Map("encbound_eh_free_exception", V, {P});
        if (N == "__cxa_throw") return Map("encbound_eh_throw", V, {P,P,P});
        if (N == "__cxa_begin_catch") return Map("encbound_eh_begin_catch", P, {P});
        if (N == "__cxa_get_exception_ptr") return Map("encbound_eh_get_exception_ptr", P, {P});
        if (N == "__cxa_end_catch") return Map("encbound_eh_end_catch", V, {});
        if (N == "__cxa_rethrow") return Map("encbound_eh_rethrow", V, {});
        if (N == "__dynamic_cast") return Map("__encbound_app_dynamic_cast", P, {P,P,P,Z});
        if (N == "__cxa_bad_cast") return Map("__encbound_app_bad_cast", V, {});
        if (N == "__cxa_bad_typeid") return Map("__encbound_app_bad_typeid", V, {});
        if (N == "_ZSt9terminatev") return Map("encbound_cxx_fail", V, {});
        if (N == "_ZSt19uncaught_exceptionsv") return Map("encbound_eh_uncaught_exceptions", I, {});
        if (N == "_Znwm" || N == "_Znam") return Map("__encbound_app_new", P, {Z});
        if (N == "_ZnwmSt11align_val_t" || N == "_ZnamSt11align_val_t")
            return Map("__encbound_app_new_aligned", P, {Z,Z});
    }
    if (CxxLifecycleOption) {
        if (N == "__cxa_guard_acquire") return Map("encbound_cxx_guard_acquire", I, {P});
        if (N == "__cxa_guard_release") return Map("encbound_cxx_guard_release", V, {P});
        if (N == "__cxa_guard_abort") return Map("encbound_cxx_guard_abort", V, {P});
    }
    if (CxxAllocationOption) {
        if (N == "ceilf") return Map("encbound_cxx_ceilf", Type::getFloatTy(C), {Type::getFloatTy(C)});
        if (N == "abort" || N == "__cxa_pure_virtual" || N == "__cxa_deleted_virtual")
            return Map("encbound_cxx_fail", V, {});
        if (N == "__assert") return Map("encbound_cxx_assert", V, {P,I,P,P});
        if (N == "_Znwm" || N == "_Znam") return Map("encbound_cxx_new", P, {Z});
        if (N == "_ZnwmRKSt9nothrow_t" || N == "_ZnamRKSt9nothrow_t")
            return Map("encbound_cxx_new_nothrow", P, {Z,P});
        if (N == "_ZnwmSt11align_val_t" || N == "_ZnamSt11align_val_t")
            return Map("encbound_cxx_new_aligned", P, {Z,Z});
        if (N == "_ZnwmSt11align_val_tRKSt9nothrow_t" || N == "_ZnamSt11align_val_tRKSt9nothrow_t")
            return Map("encbound_cxx_new_aligned_nothrow", P, {Z,Z,P});
        if (N == "_ZdlPv" || N == "_ZdaPv") return Map("encbound_cxx_delete", V, {P});
        if (N == "_ZdlPvm" || N == "_ZdaPvm") return Map("encbound_cxx_delete_sized", V, {P,Z});
        if (N == "_ZdlPvRKSt9nothrow_t" || N == "_ZdaPvRKSt9nothrow_t")
            return Map("encbound_cxx_delete_nothrow", V, {P,P});
        if (N == "_ZdlPvSt11align_val_t" || N == "_ZdaPvSt11align_val_t")
            return Map("encbound_cxx_delete_aligned", V, {P,Z});
        if (N == "_ZdlPvmSt11align_val_t" || N == "_ZdaPvmSt11align_val_t")
            return Map("encbound_cxx_delete_sized_aligned", V, {P,Z,Z});
        if (N == "_ZdlPvSt11align_val_tRKSt9nothrow_t" || N == "_ZdaPvSt11align_val_tRKSt9nothrow_t")
            return Map("encbound_cxx_delete_aligned_nothrow", V, {P,Z,P});
    }
    if (N == "malloc") return Map("encbound_malloc", P, {Z});
    if (N == "calloc") return Map("encbound_calloc", P, {Z,Z});
    if (N == "realloc") return Map("encbound_realloc", P, {P,Z});
    if (N == "free") return Map("encbound_free", V, {P});
    if (N == "memcpy" || N == "memmove" || N == "strncpy" || N == "strncat")
        return Map(("encbound_" + N).str(), P, {P,P,Z});
    if (N == "memset") return Map("encbound_memset", P, {P,I,Z});
    if (N == "memcmp") return Map("encbound_memcmp", I, {P,P,Z});
    if (N == "strcmp") return Map("encbound_strcmp", I, {P,P});
    if (N == "strlen") return Map("encbound_strlen", Z, {P});
    if (N == "strnlen") return Map("encbound_strnlen", Z, {P,Z});
    return {"", nullptr};
}

void validateServiceABI(Function &F, FunctionType *Expected) {
    if (F.getFunctionType() != Expected || F.getCallingConv() != CallingConv::C || F.isVarArg())
        report_fatal_error(Twine("ENCBound: unsupported service ABI: ") + F.getName());
    for (unsigned A = 0; A < F.arg_size(); ++A)
        for (auto K : kAbiAttrKinds)
            if (F.hasParamAttribute(A, K))
                report_fatal_error("ENCBound: unsupported service memory ABI");
}

bool simpleCallbackABI(const CallBase &C) {
    auto Scalar = [](Type *T) { return T->isPointerTy() || T->isIntegerTy() || T->isFloatingPointTy(); };
    if (C.getCallingConv() != CallingConv::C || C.getFunctionType()->isVarArg() ||
        C.arg_size() != C.getFunctionType()->getNumParams() ||
        !(C.getType()->isVoidTy() || Scalar(C.getType()))) return false;
    for (Value *A : C.args()) if (!Scalar(A->getType())) return false;
    return true;
}

void routeServiceReferences(Module &M, SmallPtrSetImpl<Function *> &Routed) {
    SmallVector<Function *, 32> Originals;
    for (Function &F : M) Originals.push_back(&F);
    // Input helpers are forbidden even when only their address is taken. Do
    // this before inserting any legitimate compiler-generated declarations.
    for (Function *F : Originals)
        if (!Routed.contains(F) && !F->use_empty() && (isPrivilegedHelper(F->getName()) || isSetjmpLike(F->getName())))
            report_fatal_error("ENCBound: unsupported privileged function reference");
    for (Function *F : Originals) {
        if (Routed.contains(F)) continue;
        if (!F->isDeclaration() || F->isIntrinsic() || F->use_empty()) continue;
        // Bare inventory entries denote an application-owned definition in
        // another unit, including a user-provided allocation implementation.
        if (admittedInventory().admitted.contains(F->getName()) &&
            !admittedInventory().redirect.contains(F->getName())) continue;
        auto Mapping = serviceMapping(M, F->getName());
        auto It = admittedInventory().redirect.find(F->getName());
        if (Mapping.first.empty() && It != admittedInventory().redirect.end())
            Mapping = {It->second, F->getFunctionType()};
        if (Mapping.first.empty()) {
            if (F->getName() == "snprintf") {
                // Only the existing literal-format direct call transformation
                // has a contract; the fixed wrapper is not a variadic target.
                for (User *U : F->users()) {
                    auto *C = dyn_cast<CallInst>(U);
                    if (!C || C->getCalledFunction() != F)
                        report_fatal_error("ENCBound: unsupported snprintf address use");
                }
            } else if (!isAdmittedExternal(F->getName()))
                report_fatal_error(Twine("ENCBound: unsupported external function reference: ") + F->getName());
            continue;
        }
        validateServiceABI(*F, Mapping.second);
        // Validate direct call types too: opaque pointers permit a call-site
        // prototype different from the declaration's prototype.
        for (Function &Caller : M) for (Instruction &I : instructions(Caller))
            if (auto *C = dyn_cast<CallBase>(&I))
                if (C->getCalledOperand()->stripPointerCasts() == F &&
                    (C->getFunctionType() != Mapping.second || C->getCallingConv() != CallingConv::C))
                    report_fatal_error("ENCBound: unsupported service call ABI");
        auto *Target = M.getFunction(Mapping.first);
        // The checked RTTI implementation itself uses dynamic_cast on type
        // descriptors. Its application-owned definition may share this unit;
        // its body still receives the ordinary instrumentation below.
        bool AppRTTI = CxxEHOption && F->getName()=="__dynamic_cast" &&
                       Mapping.first=="__encbound_app_dynamic_cast";
        if (Target && ((!Target->isDeclaration() && !AppRTTI) || Target->getFunctionType() != Mapping.second))
            report_fatal_error("ENCBound: unsupported adapter collision");
        Target = cast<Function>(M.getOrInsertFunction(Mapping.first, Mapping.second).getCallee());
        validateServiceABI(*Target, Mapping.second);
        F->replaceAllUsesWith(Target);
        Routed.insert(Target);
    }
}

cl::opt<bool> AggregateABIOption("encbound-aggregate-abi", cl::init(false), cl::Hidden);

// Fingerprint structural types, not translation-unit-local LLVM type names.
void abiType(raw_ostream &O, Type *T) {
    if (auto *S = dyn_cast<StructType>(T)) {
        if (S->isOpaque()) report_fatal_error("ENCBound: unsupported opaque ABI type");
        O << (S->isPacked() ? "packed{" : "{");
        for (Type *E : S->elements()) { abiType(O, E); O << ';'; }
        O << '}';
    } else if (auto *A = dyn_cast<ArrayType>(T)) {
        O << '[' << A->getNumElements() << ':'; abiType(O, A->getElementType()); O << ']';
    } else T->print(O);
}
std::string aggregateSignature(FunctionType *T, AttributeList Attrs, unsigned CC) {
    std::string Text;
    raw_string_ostream O(Text);
    O << "encbound-abi-v1:" << CC << ':';
    abiType(O, T->getReturnType());
    for (unsigned I = 0; I < T->getNumParams(); ++I) {
        O << '|'; abiType(O, T->getParamType(I));
        for (auto K : {Attribute::ByVal, Attribute::StructRet}) {
            Attribute A = Attrs.getParamAttr(I, K);
            if (A.isValid()) {
                O << ':' << Attribute::getNameFromAttrKind(K) << ':';
                abiType(O, A.getValueAsType());
                O << ':' << Attrs.getParamAlignment(I).valueOrOne().value();
            }
        }
        for (auto K : {Attribute::SExt, Attribute::ZExt, Attribute::InReg})
            if (Attrs.hasParamAttr(I, K)) O << ':' << Attribute::getNameFromAttrKind(K);
    }
    for (auto K : {Attribute::SExt, Attribute::ZExt, Attribute::InReg})
        if (Attrs.hasRetAttr(K)) O << ":ret:" << Attribute::getNameFromAttrKind(K);
    return Text;
}
bool hasAggregateABI(AttributeList A, unsigned Count) {
    bool Found = false;
    for (unsigned I = 0; I < Count; ++I) {
        for (auto K : {Attribute::InAlloca, Attribute::Preallocated, Attribute::ByRef})
            if (A.hasParamAttr(I, K)) report_fatal_error("ENCBound: unsupported implicit argument ABI");
        Found |= A.hasParamAttr(I, Attribute::ByVal) || A.hasParamAttr(I, Attribute::StructRet);
    }
    return Found;
}
void normalizeAggregateABI(Module &M, SmallPtrSetImpl<Function *> &Private) {
    DenseMap<Function *, std::string> Signatures;
    SmallVector<Function *, 16> Work;
    std::string Records;
    for (Function &F : M) {
        if (F.isIntrinsic()) continue;
        if (F.getMetadata("encbound.byval"))
            report_fatal_error("ENCBound: unsupported source ABI metadata");
        if (F.getName().starts_with("__encbound_abi_"))
            report_fatal_error("ENCBound: unsupported source private ABI symbol");
        if (!hasAggregateABI(F.getAttributes(), F.arg_size())) continue;
        if (F.isVarArg() || (F.getCallingConv() != CallingConv::C &&
            !(F.hasLocalLinkage() && F.getCallingConv() == CallingConv::Fast)) ||
            (F.isDeclaration() && (!isAdmittedExternal(F.getName()) ||
             admittedInventory().redirect.contains(F.getName()))))
            report_fatal_error("ENCBound: unsupported aggregate boundary ABI");
        Work.push_back(&F);
        Signatures[&F] = aggregateSignature(F.getFunctionType(), F.getAttributes(), F.getCallingConv());
    }
    // Validate original agreement before erasing any ABI attributes.
    for (Function &F : M) for (Instruction &I : instructions(F)) {
        auto *C = dyn_cast<CallBase>(&I);
        if (!C || isa<IntrinsicInst>(C)) continue;
        bool Changed = hasAggregateABI(C->getAttributes(), C->arg_size());
        auto *Target = dyn_cast<Function>(C->getCalledOperand()->stripPointerCasts());
        if (!Changed && (!Target || !Signatures.count(Target))) continue;
        if (!Changed || C->isMustTailCall() || C->getFunctionType()->isVarArg() ||
            (C->getCallingConv() != CallingConv::C &&
             !(Target && Target->hasLocalLinkage() && C->getCallingConv() == CallingConv::Fast)) || C->hasOperandBundles())
            report_fatal_error("ENCBound: unsupported aggregate call ABI");
        auto Signature = aggregateSignature(C->getFunctionType(), C->getAttributes(), C->getCallingConv());
        if (Target && (!Signatures.count(Target) || Signatures[Target] != Signature))
            report_fatal_error("ENCBound: unsupported mismatched aggregate ABI");
        if (!Target && !CallbacksOption)
            report_fatal_error("ENCBound: unsupported aggregate callback without callbacks");
        if (auto *Call=dyn_cast<CallInst>(C)) Call->setTailCallKind(CallInst::TCK_None);
        for (unsigned A = 0; A < C->arg_size(); ++A) {
            C->removeParamAttr(A, Attribute::ByVal);
            C->removeParamAttr(A, Attribute::StructRet);
        }
    }
    for (Function *F : Work) {
        MD5 Hash; Hash.update(Signatures[F]); MD5::MD5Result Result; Hash.final(Result);
        SmallString<32> Hex; MD5::stringifyResult(Result, Hex);
        std::string Name = ("__encbound_abi_" + Hex + "_" + F->getName()).str();
        if (M.getNamedValue(Name)) report_fatal_error("ENCBound: private ABI name collision");
        Records += (F->isDeclaration() ? "R " : "D ") + Name + " " + Signatures[F] + "\n";
        F->setName(Name);
        if (F->hasComdat()) F->setComdat(M.getOrInsertComdat(Name));
        Private.insert(F);
        SmallVector<Metadata *, 4> CopyRecords;
        for (Argument &A : F->args()) {
            if (A.hasByValAttr() && !F->isDeclaration()) {
                Type *T = A.getParamByValType();
                auto Size = M.getDataLayout().getTypeAllocSize(T);
                if (Size.isScalable() || !Size.getFixedValue() || Size.getFixedValue() > (1ull << 30))
                    report_fatal_error("ENCBound: unsupported byval size");
                Align Alignment = A.getParamAlign().value_or(M.getDataLayout().getABITypeAlign(T));
                IRBuilder<> B(&*F->getEntryBlock().getFirstInsertionPt());
                auto *Copy = B.CreateAlloca(T, nullptr, "encbound.byval.copy");
                Copy->setAlignment(Alignment);
                A.replaceAllUsesWith(Copy);
                // Insert after replacement: the incoming argument is only the
                // source of this exact-size, subsequently checked copy.
                B.CreateMemCpy(Copy, Alignment, &A, Alignment, Size.getFixedValue());
                auto MetaInt = [&](uint64_t V) { return ConstantAsMetadata::get(ConstantInt::get(Type::getInt64Ty(M.getContext()), V)); };
                CopyRecords.push_back(MDNode::get(M.getContext(), {MetaInt(A.getArgNo()), MetaInt(Size.getFixedValue()), MetaInt(Alignment.value())}));
            }
            F->removeParamAttr(A.getArgNo(), Attribute::ByVal);
            F->removeParamAttr(A.getArgNo(), Attribute::StructRet);
        }
        if (!CopyRecords.empty()) F->setMetadata("encbound.byval", MDNode::get(M.getContext(), CopyRecords));
    }
    if (!Records.empty()) {
        auto *Init = ConstantDataArray::getString(M.getContext(), Records, true);
        auto *G = new GlobalVariable(M, Init->getType(), true, GlobalValue::PrivateLinkage, Init, "__encbound_abi_records");
        G->setSection(".encbound.abi"); G->setAlignment(Align(1)); appendToUsed(M, {G});
    }
}

// BASELINE uses the same explicit C++ exhaustion policy, with raw malloc/free.
// It does not route C services, normalize ABI, or instrument memory.
struct ENCBoundCxxBaselinePass : PassInfoMixin<ENCBoundCxxBaselinePass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        if (CxxLifecycleOption) markLifecycle(M);
        // Exception-mode BASELINE retains ordinary SDK C++ allocation/RTTI/EH.
        if (CxxEHOption) { createCxxEHBoundaries(M,true); return PreservedAnalyses::none(); }
        if (!CxxAllocationOption) return PreservedAnalyses::all();
        SmallVector<Function *, 16> Work;
        for (Function &F : M) if (F.isDeclaration() && !F.use_empty() &&
            (F.getName().starts_with("_Z") || F.getName()=="abort" || F.getName()=="ceilf" || F.getName()=="__assert" ||
             F.getName()=="__cxa_pure_virtual" || F.getName()=="__cxa_deleted_virtual")) Work.push_back(&F);
        for (Function *F : Work) {
            if (admittedInventory().admitted.contains(F->getName()) &&
                !admittedInventory().redirect.contains(F->getName())) continue;
            auto S = serviceMapping(M, F->getName());
            if (S.first.empty()) continue;
            validateServiceABI(*F, S.second);
            auto *Target = M.getFunction(S.first);
            if (Target && (!Target->isDeclaration() || Target->getFunctionType() != S.second))
                report_fatal_error("ENCBound: unsupported baseline adapter collision");
            F->replaceAllUsesWith(M.getOrInsertFunction(S.first, S.second).getCallee());
        }
        return PreservedAnalyses::none();
    }
};

// Independently validate the transformed entry copy, after instrumentation and
// each optional pass. Memory-access verification still checks the range helpers.
void verifyAggregateCopies(Function &F) {
    auto *Records = F.getMetadata("encbound.byval");
    if (!Records) return;
    auto Fail = [&]() { report_fatal_error(Twine("ENCBound: validation failed (byval entry copy) in ") + F.getName()); };
    for (auto &Operand : Records->operands()) {
        auto *Record = dyn_cast<MDNode>(Operand);
        if (!Record || Record->getNumOperands()!=3 || F.isDeclaration()) Fail();
        uint64_t Values[3];
        for (unsigned I=0; I<3; ++I) {
            auto *V = mdconst::dyn_extract<ConstantInt>(Record->getOperand(I));
            if (!V || V->getBitWidth()!=64) Fail();
            Values[I]=V->getZExtValue();
        }
        if (Values[0]>=F.arg_size() || !Values[1] || !isPowerOf2_64(Values[2])) Fail();
        Argument *A = F.getArg(Values[0]);
        if (!A->hasOneUse()) Fail();
        auto *Bits = dyn_cast<PtrToIntInst>(*A->user_begin());
        if (!Bits || !Bits->hasOneUse()) Fail();
        auto *Check = dyn_cast<CallInst>(*Bits->user_begin());
        if (!Check || !namedCall(*Check,"encbound_require") || Check->getArgOperand(0)!=Bits || !Check->hasOneUse()) Fail();
        auto *Raw = dyn_cast<IntToPtrInst>(*Check->user_begin());
        if (!Raw || !Raw->hasOneUse()) Fail();
        auto *Copy = dyn_cast<MemCpyInst>(*Raw->user_begin());
        auto *Length = Copy ? dyn_cast<ConstantInt>(Copy->getLength()) : nullptr;
        if (!Copy || Copy->getSource()!=Raw || !Length || Length->getZExtValue()!=Values[1] ||
            Copy->getParent()!=&F.getEntryBlock() || Copy->isVolatile()) Fail();
        auto *DstRaw = dyn_cast<IntToPtrInst>(Copy->getDest());
        auto *DstCheck = DstRaw ? dyn_cast<CallInst>(DstRaw->getOperand(0)) : nullptr;
        auto *DstBits = DstCheck && namedCall(*DstCheck,"encbound_require") ? dyn_cast<PtrToIntInst>(DstCheck->getArgOperand(0)) : nullptr;
        auto *Cap = DstBits ? dyn_cast<IntToPtrInst>(DstBits->getPointerOperand()) : nullptr;
        auto *Mint = Cap ? dyn_cast<CallInst>(Cap->getOperand(0)) : nullptr;
        AllocaInst *Slot=nullptr; uint64_t Size=0;
        if (!mintedLocal(Mint,Slot,Size) || Size<Values[1] || Slot->getAlign().value()<Values[2]) Fail();
        DominatorTree DT(F);
        for (User *U : Cap->users()) {
            if (U==DstBits) continue;
            auto *Use = dyn_cast<Instruction>(U);
            if (!Use || !DT.dominates(Copy,Use)) Fail();
        }
    }
}
