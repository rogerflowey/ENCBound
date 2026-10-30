// Bounded Itanium EH admission. The SDK unwinder owns the landingpad token;
// application code only receives the separately allocated payload capability.
namespace cxx_eh {
[[noreturn]] inline void reject(const Twine &Why) {
    report_fatal_error(Twine("ENCBound: unsupported C++ EH/RTTI: ") + Why);
}
inline bool pair(Type *T) {
    auto *S=dyn_cast<StructType>(T);
    return S && !S->isPacked() && S->getNumElements()==2 &&
           S->getElementType(0)->isPointerTy() && S->getElementType(1)->isIntegerTy(32);
}
inline bool callNamed(const Value *V, StringRef Name) {
    auto *C=dyn_cast<CallBase>(V);
    return C && C->getCalledFunction() && C->getCalledFunction()->getName()==Name;
}
inline bool component(const Value *V, unsigned Index, unsigned Depth=0);
inline bool packet(const Value *V, unsigned Depth=0) {
    if (Depth>64 || !pair(V->getType())) return false;
    if (isa<LandingPadInst>(V)) return true;
    if (auto *P=dyn_cast<PHINode>(V)) {
        for (Value *I:P->incoming_values()) if (!packet(I,Depth+1)) return false;
        return P->getNumIncomingValues()!=0;
    }
    auto *I=dyn_cast<InsertValueInst>(V);
    if (!I || I->getNumIndices()!=1 || *I->idx_begin()!=1 ||
        !component(I->getInsertedValueOperand(),1,Depth+1)) return false;
    auto *First=dyn_cast<InsertValueInst>(I->getAggregateOperand());
    return First && First->getNumIndices()==1 && *First->idx_begin()==0 &&
           (isa<PoisonValue>(First->getAggregateOperand()) || isa<UndefValue>(First->getAggregateOperand())) &&
           component(First->getInsertedValueOperand(),0,Depth+1);
}
inline bool component(const Value *V, unsigned Index, unsigned Depth) {
    if (Depth>64) return false;
    if (auto *E=dyn_cast<ExtractValueInst>(V))
        return E->getNumIndices()==1 && *E->idx_begin()==Index && packet(E->getAggregateOperand(),Depth+1);
    if (auto *P=dyn_cast<PHINode>(V)) {
        for (Value *I:P->incoming_values()) if (!component(I,Index,Depth+1)) return false;
        return P->getNumIncomingValues()!=0;
    }
    return false;
}
inline bool tokenConsumer(const CallBase &C, const Value *V) {
    if (!C.getCalledFunction() || C.arg_size()!=1 || C.getArgOperand(0)!=V ||
        C.getCallingConv()!=CallingConv::C || C.hasOperandBundles()) return false;
    StringRef N=C.getCalledFunction()->getName();
    return N=="__cxa_begin_catch" || N=="__cxa_get_exception_ptr" ||
           N=="encbound_eh_begin_catch" || N=="encbound_eh_get_exception_ptr" ||
           N=="encbound_eh_terminate";
}
inline bool packetUses(const Value *V, unsigned Depth);
inline bool tokenUses(const Value *V, unsigned Depth=0) {
    if (Depth>64) return false;
    for (const User *U:V->users()) {
        if (auto *P=dyn_cast<PHINode>(U)) {
            if (component(P,0) && tokenUses(P,Depth+1)) continue;
        }
        if (auto *I=dyn_cast<InsertValueInst>(U)) {
            if (I->getNumIndices()==1 && *I->idx_begin()==0 && I->getInsertedValueOperand()==V &&
                (isa<PoisonValue>(I->getAggregateOperand()) || isa<UndefValue>(I->getAggregateOperand()))) {
                bool Valid=true;
                for (const User *W:I->users()) if (!packet(W) || !packetUses(W,Depth+1)) Valid=false;
                if (Valid) continue;
            }
        }
        if (auto *C=dyn_cast<CallBase>(U); C && tokenConsumer(*C,V)) continue;
        return false;
    }
    return true;
}
inline bool packetUses(const Value *V, unsigned Depth=0) {
    if (Depth>64) return false;
    for (const User *U:V->users()) {
        if (auto *R=dyn_cast<ResumeInst>(U); R && R->getValue()==V) continue;
        if (auto *P=dyn_cast<PHINode>(U)) {
            if (packet(P) && packetUses(P,Depth+1)) continue;
        }
        if (auto *E=dyn_cast<ExtractValueInst>(U)) {
            if (E->getNumIndices()==1 && (*E->idx_begin()==1 ||
                (*E->idx_begin()==0 && tokenUses(E)))) continue;
        }
        return false;
    }
    return true;
}
inline bool metadataName(StringRef N) {
    return N.starts_with("_ZTI") || N.starts_with("_ZTS") || N.starts_with("_ZTV") || N.starts_with("_ZTT");
}
inline bool abiVtable(StringRef N) {
    return N=="_ZTVN10__cxxabiv117__class_type_infoE" ||
           N=="_ZTVN10__cxxabiv120__si_class_type_infoE" ||
           N=="_ZTVN10__cxxabiv121__vmi_class_type_infoE" ||
           N=="_ZTVN10__cxxabiv123__fundamental_type_infoE" ||
           N=="_ZTVN10__cxxabiv119__pointer_type_infoE" ||
           N=="_ZTVN10__cxxabiv116__enum_type_infoE" ||
           N=="_ZTVN10__cxxabiv120__function_type_infoE";
}
inline bool stdABI(StringRef N) {
    for (StringRef Class:{"St9exception", "St9bad_alloc", "St20bad_array_new_length",
                          "St8bad_cast", "St10bad_typeid", "St9type_info",
                          "St11logic_error", "St13runtime_error", "St12domain_error",
                          "St16invalid_argument", "St12length_error", "St12out_of_range",
                          "St11range_error", "St14overflow_error", "St15underflow_error",
                          "St12bad_weak_ptr", "St17bad_function_call", "St19bad_optional_access",
                          "St18bad_variant_access", "St12bad_any_cast", "St17__libcpp_refstring"})
        if (N.starts_with(("_ZN"+Class).str()) || N.starts_with(("_ZNK"+Class).str())) return true;
    for (StringRef Class:{"17__class_type_info", "20__si_class_type_info", "21__vmi_class_type_info",
                          "23__fundamental_type_info", "19__pointer_type_info", "16__enum_type_info",
                          "16__shim_type_info", "17__pbase_type_info", "17__array_type_info",
                          "20__function_type_info", "29__pointer_to_member_type_info"})
        if (N.starts_with(("_ZN10__cxxabiv1"+Class).str()) ||
            N.starts_with(("_ZNK10__cxxabiv1"+Class).str())) return true;
    return N=="_ZSt7nothrow";
}
inline bool boundaryCallback(Value *V) {
    auto *F=dyn_cast<Function>(V);
    return F && F->getName().starts_with("__encbound_eh_callback_") &&
           F->getMetadata("encbound.eh.boundary") && !F->isDeclaration();
}
inline GlobalVariable *baseGlobal(Constant *C) {
    return dyn_cast<GlobalVariable>(C->stripPointerCasts());
}
inline bool functionPointer(GlobalVariable *G, unsigned Depth=0) {
    if (Depth>32) reject("exception pointer metadata depth");
    if (!G || !G->hasInitializer()) return false;
    auto *S=dyn_cast<ConstantStruct>(G->getInitializer());
    auto *V=S && S->getNumOperands() ? dyn_cast<GEPOperator>(S->getOperand(0)) : nullptr;
    auto *Table=V ? dyn_cast<GlobalVariable>(V->getPointerOperand()) : nullptr;
    if (!Table) return false;
    StringRef N=Table->getName(); N.consume_front("__encbound_type_");
    if (N=="_ZTVN10__cxxabiv120__function_type_infoE") return true;
    if (N=="_ZTVN10__cxxabiv119__pointer_type_infoE" && S->getNumOperands()==4)
        return functionPointer(dyn_cast<GlobalVariable>(S->getOperand(3)),Depth+1);
    return false;
}
inline void metadata(Module &M, SmallPtrSetImpl<Function *> &Routed, bool Verify=false) {
    auto Original=[&](StringRef N) { if (Verify) N.consume_front("__encbound_type_"); return N; };
    SmallVector<GlobalValue *,64> Rename;
    for (GlobalVariable &G:M.globals()) {
        StringRef N=Original(G.getName());
        if (!metadataName(N) && !stdABI(N)) continue;
        if (G.isThreadLocal() || G.getAddressSpace()!=0) reject("metadata storage");
        // LLVM declares these exact immutable ABI vtables as mutable externals.
        // Their application-owned definitions and selected image are audited.
        if (abiVtable(N) && G.isDeclaration()) G.setConstant(true);
        if (!G.isConstant()) reject(Twine("mutable type metadata: ")+N);
        if (N.starts_with("_ZTI") && G.hasInitializer()) {
            auto *S=dyn_cast<ConstantStruct>(G.getInitializer());
            auto *V=S && S->getNumOperands()>=2 ? dyn_cast<GEPOperator>(S->getOperand(0)) : nullptr;
            auto *Table=V ? dyn_cast<GlobalVariable>(V->getPointerOperand()) : nullptr;
            APInt Offset(64,0);
            if (!Table || !abiVtable(Original(Table->getName())) || !V->accumulateConstantOffset(M.getDataLayout(),Offset) ||
                Offset!=16) reject(Twine("unknown type descriptor: ")+N);
            auto *Name=dyn_cast<GlobalVariable>(S->getOperand(1));
            if (!Name || !Original(Name->getName()).starts_with("_ZTS") || !Name->isConstant())
                reject("type descriptor name ownership");
            StringRef Kind=Original(Table->getName());
            if (Kind=="_ZTVN10__cxxabiv121__vmi_class_type_infoE") {
                auto *Flags=S->getNumOperands()>=6 ? dyn_cast<ConstantInt>(S->getOperand(2)) : nullptr;
                auto *Count=Flags ? dyn_cast<ConstantInt>(S->getOperand(3)) : nullptr;
                // Preserve the pinned SDK's graph behavior, including private
                // bases and first-match repeated bases. Check the descriptor
                // representation here; do not impose different cast semantics.
                if (!Flags || !Flags->getType()->isIntegerTy(32) || (Flags->getZExtValue()&~3ull) || !Count ||
                    !Count->getType()->isIntegerTy(32) || !Count->getZExtValue() || Count->getZExtValue()>64 ||
                    S->getNumOperands()!=4+2*Count->getZExtValue())
                    reject("invalid inheritance metadata");
                for (unsigned J=4;J<S->getNumOperands();J+=2) {
                    auto *Base=dyn_cast<GlobalVariable>(S->getOperand(J));
                    auto *Bits=dyn_cast<ConstantInt>(S->getOperand(J+1));
                    if (!Base || !Original(Base->getName()).starts_with("_ZTI") || !Base->isConstant() || !Bits || !Bits->getType()->isIntegerTy(64) ||
                        (Bits->getZExtValue()&252) ||
                        (!(Bits->getZExtValue()&1) && Bits->isNegative()))
                        reject("invalid base metadata");
                    if ((Bits->getZExtValue()&1) &&
                        ((Bits->getSExtValue()>>8)>=-16 || ((Bits->getSExtValue()>>8)%8)))
                        reject("invalid virtual-base vtable offset");
                }
            } else if (Kind=="_ZTVN10__cxxabiv119__pointer_type_infoE") {
                auto *Flags=S->getNumOperands()==4 ? dyn_cast<ConstantInt>(S->getOperand(2)) : nullptr;
                auto *Pointee=Flags ? dyn_cast<GlobalVariable>(S->getOperand(3)) : nullptr;
                if (!Flags || !Flags->getType()->isIntegerTy(32) || (Flags->getZExtValue()&~7ull) ||
                    !Pointee || !Pointee->isConstant() || !Original(Pointee->getName()).starts_with("_ZTI"))
                    reject("incomplete/member pointer metadata");
                // Function and function-pointer identity are ordinary metadata.
                // Unsupported exception conversions are rejected at throw/catch
                // uses, rather than blocking std::function's type comparisons.
            } else if (Kind=="_ZTVN10__cxxabiv120__si_class_type_infoE") {
                auto *Base=S->getNumOperands()==3 ? dyn_cast<GlobalVariable>(S->getOperand(2)) : nullptr;
                if (!Base || !Base->isConstant() || !Original(Base->getName()).starts_with("_ZTI"))
                    reject("single base metadata");
            } else if (S->getNumOperands()!=2) {
                reject("descriptor layout");
            }
        }
        Rename.push_back(&G);
    }
    if (Verify) return;
    for (Function &F:M) if (stdABI(F.getName())) {
        if (!F.isDeclaration() || admittedInventory().admitted.contains(F.getName())) Routed.insert(&F);
        Rename.push_back(&F);
    }
    for (GlobalAlias &A:M.aliases()) if (stdABI(A.getName()) || metadataName(A.getName())) Rename.push_back(&A);
    for (GlobalValue *G:Rename) {
        std::string Name=("__encbound_type_"+G->getName()).str();
        if (M.getNamedValue(Name)) reject("private metadata symbol collision");
        G->setName(Name);
        if (auto *O=dyn_cast<GlobalObject>(G); O && O->hasComdat()) O->setComdat(M.getOrInsertComdat(Name));
    }
}
} // namespace cxx_eh

void verifyCxxEHBoundary(Function &F) {
    using namespace cxx_eh;
    auto *MD=F.getMetadata("encbound.eh.boundary");
    bool Entry=F.getName().starts_with("__encbound_eh_entry_");
    bool Callback=F.getName().starts_with("__encbound_eh_callback_");
    if (!MD && !Entry && !Callback) return;
    auto *V=MD && MD->getNumOperands()==1 ? dyn_cast<ValueAsMetadata>(MD->getOperand(0)) : nullptr;
    auto *Target=V ? dyn_cast<Function>(V->getValue()) : nullptr;
    if (!Target || (!Entry && !Callback) || Target==&F || F.size()!=3 ||
        Target->getFunctionType()!=F.getFunctionType() || F.getCallingConv()!=CallingConv::C)
        reject("boundary identity/ABI");
    auto *Call=dyn_cast<InvokeInst>(F.getEntryBlock().getTerminator());
    if (!Call || F.getEntryBlock().size()!=1 || Call->getCalledFunction()!=Target ||
        Call->arg_size()!=F.arg_size() || Call->getNormalDest()==Call->getUnwindDest())
        reject("boundary invoke");
    for (unsigned I=0;I<F.arg_size();++I)
        if (Call->getArgOperand(I)!=F.getArg(I)) reject("boundary argument");
    auto *Done=Call->getNormalDest(), *Stop=Call->getUnwindDest();
    auto *Return=dyn_cast<ReturnInst>(Done->getTerminator());
    if (!Return || Done->size()!=(Entry ? 2u : 1u) ||
        (F.getReturnType()->isVoidTy() ? Return->getReturnValue()!=nullptr : Return->getReturnValue()!=Call) ||
        (Entry && !callNamed(&Done->front(),"encbound_eh_boundary_clean")))
        reject("boundary normal completion");
    auto *LP=dyn_cast<LandingPadInst>(&Stop->front());
    if (Stop->size()!=3 || !LP || LP->isCleanup() || LP->getNumClauses()!=1 ||
        !LP->isCatch(0) || !LP->getClause(0)->isNullValue() ||
        !callNamed(LP->getNextNode(),"encbound_cxx_fail") || !isa<UnreachableInst>(Stop->getTerminator()))
        reject("boundary termination");
}

void verifyCxxEHModule(Module &M) {
    using namespace cxx_eh;
    auto *Marker=M.getNamedGlobal("__encbound_cxx_eh_v1");
    if (bool(Marker)!=CxxEHOption) reject("mixed EH feature mode");
    if (!CxxEHOption) return;
    if (!Marker->isConstant() || Marker->getSection()!=".encbound.abi" ||
        !Marker->hasInitializer() || !isa<ConstantInt>(Marker->getInitializer()) ||
        !cast<ConstantInt>(Marker->getInitializer())->equalsInt(1)) reject("feature marker");
    SmallPtrSet<Function *,8> Ignore;
    metadata(M,Ignore,true);
    for (GlobalVariable &G:M.globals())
        if (metadataName(G.getName()) || stdABI(G.getName())) reject("raw application type ABI survived");
    for (GlobalAlias &A:M.aliases())
        if (metadataName(A.getName()) || stdABI(A.getName())) reject("raw application type ABI alias survived");
    for (StringRef Name:{"llvm.global_ctors","llvm.global_dtors"}) if (auto *G=M.getNamedGlobal(Name)) {
        auto *A=dyn_cast_or_null<ConstantArray>(G->getInitializer());
        if (!A) reject("output startup list");
        for (Value *V:A->operands()) {
            auto *R=dyn_cast<ConstantStruct>(V);
            if (!R || R->getNumOperands()!=3 || !boundaryCallback(R->getOperand(1)))
                reject("unprepared startup callback");
        }
    }
    auto &C=M.getContext(); auto *P=PointerType::get(C,0); auto *V=Type::getVoidTy(C);
    for (Function &F:M) {
        StringRef N=F.getName();
        if (stdABI(N)) reject("raw application type ABI method survived");
        if (!N.starts_with("encbound_eh_")) continue;
        if (!F.isDeclaration()) reject("application definition of private EH service");
        if (N=="encbound_eh_personality") {
            if (F.getFunctionType()!=FunctionType::get(Type::getInt32Ty(C),true)) reject("personality ABI");
            for (User *U:F.users()) {
                auto *Owner=dyn_cast<Function>(U);
                if (!Owner || !Owner->hasPersonalityFn() || Owner->getPersonalityFn()!=&F) reject("personality address escape");
            }
            continue;
        }
        FunctionType *Expected=nullptr;
        for (StringRef Raw:{"__cxa_allocate_exception","__cxa_free_exception","__cxa_throw",
             "__cxa_begin_catch","__cxa_get_exception_ptr","__cxa_end_catch","__cxa_rethrow",
             "_ZSt19uncaught_exceptionsv"}) {
            auto Map=serviceMapping(M,Raw);
            if (Map.first==N) Expected=Map.second;
        }
        if (N=="encbound_eh_terminate") Expected=FunctionType::get(V,{P},false);
        if (N=="encbound_eh_boundary_clean") Expected=FunctionType::get(V,false);
        if (!Expected) reject("unknown private EH service");
        validateServiceABI(F,Expected);
        for (User *U:F.users()) {
            auto *Call=dyn_cast<CallBase>(U);
            if (!Call || Call->getCalledFunction()!=&F || Call->getFunctionType()!=Expected ||
                Call->getCallingConv()!=CallingConv::C || Call->hasOperandBundles()) reject("private EH service address/ABI");
            if (N=="encbound_eh_boundary_clean" && !Call->getFunction()->getName().starts_with("__encbound_eh_entry_"))
                reject("private boundary check outside wrapper");
        }
    }
}

// Small compiler-generated wrappers preserve the original application function
// and all internal calls to it. Only the SDK entry/callback points use wrappers.
void createCxxEHBoundaries(Module &M, bool Baseline) {
    using namespace cxx_eh;
    auto &C=M.getContext(); auto *P=PointerType::get(C,0);
    auto Personality=M.getOrInsertFunction("__gxx_personality_v0",FunctionType::get(Type::getInt32Ty(C),true));
    DenseMap<Function *,Function *> Callbacks;
    auto Wrap=[&](Function *F,StringRef Name,bool External) {
        if (M.getNamedValue(Name)) reject("boundary symbol collision");
        if (F->isVarArg() || F->getCallingConv()!=CallingConv::C) reject("boundary ABI");
        auto *W=Function::Create(F->getFunctionType(),External ? GlobalValue::ExternalLinkage : GlobalValue::InternalLinkage,Name,M);
        if (External) W->setVisibility(GlobalValue::HiddenVisibility);
        // Preserve native byval/sret in BASELINE. Protected ECALLs with records
        // enter via the generator's existing explicit-pointer application adapter.
        W->setAttributes(F->getAttributes());
        W->removeFnAttr(Attribute::NoUnwind);
        W->setPersonalityFn(cast<Constant>(Personality.getCallee()));
        auto *Entry=BasicBlock::Create(C,"entry",W);
        auto *Done=BasicBlock::Create(C,"return",W);
        auto *Stop=BasicBlock::Create(C,"terminate",W);
        IRBuilder<> B(Entry); SmallVector<Value *,8> Args;
        for (Argument &A:W->args()) Args.push_back(&A);
        auto *Call=B.CreateInvoke(F,Done,Stop,Args);
        Call->setAttributes(F->getAttributes());
        B.SetInsertPoint(Done);
        if (External && !Baseline)
            B.CreateCall(M.getOrInsertFunction("encbound_eh_boundary_clean",FunctionType::get(Type::getVoidTy(C),false)));
        if (F->getReturnType()->isVoidTy()) B.CreateRetVoid(); else B.CreateRet(Call);
        B.SetInsertPoint(Stop);
        auto *LP=B.CreateLandingPad(StructType::get(P,Type::getInt32Ty(C)),1);
        LP->addClause(ConstantPointerNull::get(P));
        B.CreateCall(M.getOrInsertFunction("abort",FunctionType::get(Type::getVoidTy(C),false)));
        B.CreateUnreachable();
        W->setMetadata("encbound.eh.boundary",MDNode::get(C,ValueAsMetadata::get(F)));
        return W;
    };
    auto Callback=[&](Function *F) {
        if (Callbacks.count(F)) return Callbacks[F];
        Function *W=Wrap(F,("__encbound_eh_callback_"+F->getName()).str(),false);
        Callbacks[F]=W; return W;
    };
    SmallVector<CallBase *,16> Calls;
    for (Function &F:M) for (Instruction &I:instructions(F))
        if (auto *Call=dyn_cast<CallBase>(&I))
            if (Call->getCalledFunction() && (Call->getCalledFunction()->getName()=="__cxa_throw" ||
                                            Call->getCalledFunction()->getName()=="__cxa_atexit")) Calls.push_back(Call);
    for (CallBase *Call:Calls) {
        unsigned Arg=Call->getCalledFunction()->getName()=="__cxa_throw" ? 2 : 0;
        if (Call->arg_size()!=3) reject("callback registration ABI");
        Value *V=Call->getArgOperand(Arg);
        if (isa<ConstantPointerNull>(V)) continue;
        auto *F=dyn_cast<Function>(V->stripPointerCastsAndAliases());
        if (!F || F->getFunctionType()!=FunctionType::get(Type::getVoidTy(C),{P},false) ||
            (F->isDeclaration() && !admittedInventory().admitted.contains(F->getName()) &&
             !(Baseline && stdABI(F->getName())))) reject("destructor ownership/ABI");
        Call->setArgOperand(Arg,Callback(F));
    }
    for (StringRef Name:{"llvm.global_ctors","llvm.global_dtors"}) if (auto *G=M.getNamedGlobal(Name)) {
        auto *A=dyn_cast_or_null<ConstantArray>(G->getInitializer());
        if (!A) reject("startup list");
        SmallVector<Constant *,8> Records;
        for (Value *V:A->operands()) {
            auto *R=dyn_cast<ConstantStruct>(V);
            auto *F=R && R->getNumOperands()==3 ? dyn_cast<Function>(R->getOperand(1)) : nullptr;
            if (!F) reject("startup entry");
            Records.push_back(ConstantStruct::get(cast<StructType>(R->getType()),
                {cast<Constant>(R->getOperand(0)),Callback(F),cast<Constant>(R->getOperand(2))}));
        }
        G->setInitializer(ConstantArray::get(A->getType(),Records));
    }
    if (!CxxEHEntries.empty()) {
        auto File=MemoryBuffer::getFile(CxxEHEntries);
        if (!File) reject("cannot read ECALL entry inventory");
        SmallVector<StringRef,16> Names; (*File)->getBuffer().split(Names,'\n');
        for (StringRef N:Names) {
            N=N.trim(); if (N.empty()) continue;
            auto *F=M.getFunction(N);
            if (!F || F->isDeclaration()) continue;
            if (!Baseline && hasAggregateABI(F->getAttributes(),F->arg_size())) reject("ECALL requires generated record adapter");
            Wrap(F,("__encbound_eh_entry_"+N).str(),true);
        }
    }
    auto *G=new GlobalVariable(M,Type::getInt64Ty(C),true,GlobalValue::InternalLinkage,
        ConstantInt::get(Type::getInt64Ty(C),1),"__encbound_cxx_eh_v1");
    G->setSection(".encbound.abi"); appendToUsed(M,{G});
}

void verifyCxxEH(Function &F, bool Output) {
    using namespace cxx_eh;
    if (CxxEHOption) verifyCxxEHBoundary(F);
    if (F.hasPersonalityFn()) {
        auto *P=dyn_cast<Function>(F.getPersonalityFn());
        if (!CxxEHOption || !P || P->getName()!="encbound_eh_personality" || !P->isDeclaration())
            reject("personality");
    }
    for (Instruction &I:instructions(F)) {
        if (auto *LP=dyn_cast<LandingPadInst>(&I)) {
            if (!CxxEHOption || !F.hasPersonalityFn() || !pair(LP->getType()) || !packetUses(LP))
                reject("landingpad/token escape");
            for (unsigned J=0;J<LP->getNumClauses();++J) {
                auto *G=dyn_cast<GlobalVariable>(LP->getClause(J));
                if (!LP->isCatch(J) || (!LP->getClause(J)->isNullValue() &&
                    (!G || !G->isConstant() || !G->getName().starts_with("__encbound_type__ZTI"))))
                    reject("catch filter/type metadata");
                if (functionPointer(G)) reject("function-pointer exception matching");
            }
        }
        if (auto *R=dyn_cast<ResumeInst>(&I))
            if (!CxxEHOption || !packet(R->getValue()) || !packetUses(R->getValue())) reject("resume token");
        if (isa<CatchSwitchInst>(I) || isa<CatchReturnInst>(I) || isa<CleanupReturnInst>(I) || isa<FuncletPadInst>(I))
            reject("foreign EH instructions");
        auto *C=dyn_cast<CallBase>(&I);
        if (!C || !C->getCalledFunction()) continue;
        StringRef N=C->getCalledFunction()->getName();
        if (N=="encbound_eh_begin_catch" || N=="encbound_eh_get_exception_ptr" || N=="encbound_eh_terminate") {
            if (!CxxEHOption || C->arg_size()!=1 || !component(C->getArgOperand(0),0) ||
                !tokenConsumer(*C,C->getArgOperand(0))) reject("forged catch token");
        }
        if (N=="encbound_eh_personality") reject("application personality call");
        if (N=="encbound_cxx_atexit") {
            // Lifecycle registration also exists in the no-EH configuration.
            // Its callback is an ordinary owned application function; only the
            // EH configuration requires a terminating exception wrapper.
            auto *Dtor=C->arg_size()==2 ? dyn_cast<Function>(C->getArgOperand(0)) : nullptr;
            auto &Context=F.getContext(); auto *P=PointerType::get(Context,0);
            if (!CxxLifecycleOption || !CallbacksOption || !ProtectedGlobalsOption ||
                !Dtor || Dtor->getCallingConv()!=CallingConv::C ||
                Dtor->getFunctionType()!=FunctionType::get(Type::getVoidTy(Context),{P},false) ||
                (Dtor->isDeclaration() && !admittedInventory().admitted.contains(Dtor->getName())) ||
                C->getFunctionType()!=FunctionType::get(Type::getInt32Ty(Context),{P,P},false) ||
                C->getCallingConv()!=CallingConv::C || C->hasOperandBundles())
                reject("destructor registration ABI/ownership");
            if (CxxEHOption && !boundaryCallback(Dtor)) reject("unprepared destructor registration");
        }
        if (N=="encbound_eh_throw") {
            auto *Type=C->arg_size()==3 ? dyn_cast<GlobalVariable>(C->getArgOperand(1)) : nullptr;
            auto *Dtor=C->arg_size()==3 ? dyn_cast<Function>(C->getArgOperand(2)) : nullptr;
            if (!Type || !Type->isConstant() || !Type->getName().starts_with("__encbound_type__ZTI") ||
                (!isa<ConstantPointerNull>(C->getArgOperand(2)) && !boundaryCallback(Dtor)))
                reject("throw metadata/destructor ownership");
            if (functionPointer(Type)) reject("function-pointer exception matching");
        }
        if (C->getIntrinsicID()==Intrinsic::eh_typeid_for) {
            auto *G=C->arg_size()==1 ? dyn_cast<GlobalVariable>(C->getArgOperand(0)) : nullptr;
            if (!CxxEHOption || !G || !G->isConstant() || !G->getName().starts_with("__encbound_type__ZTI"))
                reject("type selector operand");
        }
        if (Output && (N.starts_with("__cxa_") || N.starts_with("_Unwind_")))
            reject("raw exception ABI survived");
    }
}

void normalizeCxxEHTokens(Function &F) {
    using namespace cxx_eh;
    SmallVector<AllocaInst *,8> Cells;
    for (Instruction &I:instructions(F)) {
        if (!component(&I,0)) continue;
        for (User *U:I.users()) {
            auto *S=dyn_cast<StoreInst>(U);
            if (!S) continue;
            auto *A=dyn_cast<AllocaInst>(S->getPointerOperand());
            if (!A || !A->isStaticAlloca() || S->getValueOperand()!=&I || !isAllocaPromotable(A))
                reject("escaping unwind spill cell");
            if (!is_contained(Cells,A)) Cells.push_back(A);
        }
    }
    for (AllocaInst *A:Cells) for (User *U:A->users())
        if (auto *S=dyn_cast<StoreInst>(U); S && !component(S->getValueOperand(),0))
            reject("application-written unwind spill cell");
    // Selectors are ordinary integers, but keeping compiler spill cells in SSA
    // also preserves the canonical resume pair at frontend O0.
    for (Instruction &I:instructions(F)) if (component(&I,1))
        for (User *U:I.users()) if (auto *S=dyn_cast<StoreInst>(U)) {
            auto *A=dyn_cast<AllocaInst>(S->getPointerOperand());
            if (A && A->isStaticAlloca() && isAllocaPromotable(A) && !is_contained(Cells,A)) {
                bool Valid=true;
                for (User *W:A->users()) if (auto *T=dyn_cast<StoreInst>(W))
                    if (!component(T->getValueOperand(),1)) Valid=false;
                if (Valid) Cells.push_back(A);
            }
        }
    if (!Cells.empty()) { DominatorTree DT(F); PromoteMemToReg(Cells,DT); }
    verifyCxxEH(F,false);
}

void prepareCxxEH(Module &M, SmallPtrSetImpl<Function *> &Routed) {
    using namespace cxx_eh;
    if (!CallbacksOption || !CxxAllocationOption || !ProtectedGlobalsOption)
        reject("mode requires callbacks, C++ allocation and protected globals");
    if (CheckReuseOption!="off" || LocalProofsOption)
        reject("EH optimization combination is not validated");
    for (Function &F:M) {
        StringRef N=F.getName();
        if (F.getMetadata("encbound.eh.boundary")) reject("source boundary metadata");
        if (N.starts_with("encbound_eh_") || N.starts_with("__encbound_eh_") || N.starts_with("__encbound_type_"))
            reject("reserved ABI symbol in source");
        if (N.starts_with("_Unwind_") && !F.use_empty()) reject("manual unwinder access");
        if (N.starts_with("__cxa_") || N=="__dynamic_cast") {
            bool Lifecycle=N=="__cxa_atexit";
            if (!F.isDeclaration() || admittedInventory().admitted.contains(N) ||
                (!Lifecycle && serviceMapping(M,N).first.empty())) reject("unowned/raw C++ ABI service");
        }
    }
    for (GlobalVariable &G:M.globals())
        if (G.getName().starts_with("__encbound_type_") || G.getName().starts_with("__encbound_eh_") ||
            G.getName()=="__encbound_cxx_eh_v1") reject("reserved metadata symbol in source");
    createCxxEHBoundaries(M,false);
    if (auto *F=M.getFunction("encbound_eh_boundary_clean")) Routed.insert(F);
    // Clang emits this exact no-return helper for noexcept. Replace its private
    // token argument with one terminal service; never treat it as app data.
    if (auto *T=M.getFunction("__clang_call_terminate")) {
        auto *P=PointerType::get(M.getContext(),0);
        if (T->isDeclaration() || T->getFunctionType()!=FunctionType::get(Type::getVoidTy(M.getContext()),{P},false))
            reject("terminate helper shape");
        unsigned Calls=0;
        for (Instruction &I:instructions(T)) {
            if (auto *C=dyn_cast<CallInst>(&I)) {
                if (Calls==0 && callNamed(C,"__cxa_begin_catch") && C->arg_size()==1 && C->getArgOperand(0)==T->getArg(0)) ++Calls;
                else if (Calls==1 && callNamed(C,"_ZSt9terminatev") && C->arg_empty()) ++Calls;
                else reject("terminate helper body");
            } else if (!isa<UnreachableInst>(I)) reject("terminate helper body");
        }
        if (Calls!=2) reject("terminate helper body");
        auto *Target=cast<Function>(M.getOrInsertFunction("encbound_eh_terminate",T->getFunctionType()).getCallee());
        T->replaceAllUsesWith(Target); T->eraseFromParent(); Routed.insert(Target);
    }
    if (auto *P=M.getFunction("__gxx_personality_v0")) {
        if (!P->isDeclaration() || !P->isVarArg() || P->arg_size() || !P->getReturnType()->isIntegerTy(32))
            reject("personality ABI");
        for (User *U:P->users()) {
            auto *F=dyn_cast<Function>(U);
            if (!F || !F->hasPersonalityFn() || F->getPersonalityFn()!=P) reject("personality address use");
        }
        P->setName("encbound_eh_personality"); Routed.insert(P);
    }
    metadata(M,Routed);
}
