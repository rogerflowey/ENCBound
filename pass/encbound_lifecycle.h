// C++ lifecycle compatibility. Included inside the pass namespace.
void validateStartupLists(Module &M) {
    for (StringRef Name : {"llvm.global_ctors", "llvm.global_dtors"}) {
        auto *G = M.getGlobalVariable(Name);
        if (!G) continue;
        if (!CxxLifecycleOption || !ProtectedGlobalsOption)
            report_fatal_error("ENCBound: unsupported application constructor/destructor (enable lifecycle and protected globals)");
        auto *A = dyn_cast_or_null<ConstantArray>(G->getInitializer());
        if (!A || G->getLinkage()!=GlobalValue::AppendingLinkage || G->hasSection() ||
            !G->use_empty() || G->isThreadLocal())
            report_fatal_error("ENCBound: unsupported startup list shape");
        for (Value *V : A->operands()) {
            auto *R = dyn_cast<ConstantStruct>(V);
            auto *Priority = R && R->getNumOperands()==3 ? dyn_cast<ConstantInt>(R->getOperand(0)) : nullptr;
            auto *F = R && R->getNumOperands()==3 ? dyn_cast<Function>(R->getOperand(1)) : nullptr;
            if (!Priority || !Priority->getType()->isIntegerTy(32) || !F || F->isDeclaration() ||
                F->getCallingConv()!=CallingConv::C || F->getFunctionType()!=FunctionType::get(Type::getVoidTy(M.getContext()),false))
                report_fatal_error("ENCBound: unsupported startup function/priority");
            auto *K = dyn_cast<Constant>(R->getOperand(2));
            auto *Associated = dyn_cast_or_null<GlobalObject>(K);
            if (!K || (!K->isNullValue() && (!Associated || Associated->isDeclaration() ||
                !Associated->hasComdat() || Associated->getComdat()->getSelectionKind()!=Comdat::Any)))
                report_fatal_error("ENCBound: unsupported startup association");
        }
    }
}

void markLifecycle(Module &M) {
    auto &C=M.getContext(); auto *I64=Type::getInt64Ty(C);
    Constant *Value=ConstantInt::get(I64,1);
    // Startup lists require an early-bootstrap link anchor. Local-static-only
    // calls can also run after the existing ECALL bridge initializes the state.
    // The final ordering audit remains mandatory for startup lists.
    if (ProfileOption!="BASELINE" &&
        (M.getGlobalVariable("llvm.global_ctors") || M.getGlobalVariable("llvm.global_dtors"))) {
        auto F=M.getOrInsertFunction("encbound_early_bootstrap",FunctionType::get(Type::getVoidTy(C),false));
        Value=ConstantExpr::getPtrToInt(cast<Constant>(F.getCallee()),I64);
    }
    auto *G=new GlobalVariable(M,I64,true,GlobalValue::InternalLinkage,Value,"__encbound_lifecycle_v1");
    G->setSection(".encbound.abi"); G->setAlignment(Align(8)); appendToUsed(M,{G});
}

// __dso_handle is an SDK token. Accept only the compiler's exact registration
// operand and remove it before the global transformation can treat it as data.
void routeLifecycleRegistration(Module &M, SmallPtrSetImpl<Function *> &Routed) {
    if (!CxxLifecycleOption) return;
    if (!ProtectedGlobalsOption || !CallbacksOption)
        report_fatal_error("ENCBound: lifecycle requires protected globals and callbacks");
    auto *Dso = M.getNamedGlobal("__dso_handle");
    if (Dso && (!Dso->isDeclaration() || Dso->isThreadLocal() || Dso->getAddressSpace()!=0))
        report_fatal_error("ENCBound: unsupported application DSO handle definition");
    auto *F = M.getFunction("__cxa_atexit");
    if (F && !F->use_empty()) {
        auto &C=M.getContext(); auto *P=PointerType::get(C,0); auto *I=Type::getInt32Ty(C);
        validateServiceABI(*F,FunctionType::get(I,{P,P,P},false));
        if (!F->isDeclaration()) report_fatal_error("ENCBound: application defines SDK registration service");
        SmallVector<CallInst *,16> Calls;
        for (User *U : F->users()) {
            auto *Call=dyn_cast<CallInst>(U);
            if (!Call || Call->getCalledFunction()!=F || Call->getFunctionType()!=F->getFunctionType() ||
                Call->getCallingConv()!=CallingConv::C || Call->arg_size()!=3 || !Dso ||
                Call->getArgOperand(2)!=Dso || Call->hasOperandBundles())
                report_fatal_error("ENCBound: unsupported destructor registration/DSO operand");
            // Direct compiler registration: no hidden ABI conversion for callbacks.
            auto *Callback=dyn_cast<Function>(Call->getArgOperand(0));
            if (!Callback || Callback->getFunctionType()!=FunctionType::get(Type::getVoidTy(C),{P},false) ||
                Callback->getCallingConv()!=CallingConv::C ||
                (Callback->isDeclaration() && !admittedInventory().admitted.contains(Callback->getName())))
                report_fatal_error("ENCBound: unsupported destructor callback ABI/ownership");
            Calls.push_back(Call);
        }
        auto *T=FunctionType::get(I,{P,P},false);
        auto *Existing=M.getFunction("encbound_cxx_atexit");
        if (Existing) report_fatal_error("ENCBound: source lifecycle adapter collision");
        auto Target=M.getOrInsertFunction("encbound_cxx_atexit",T);
        Routed.insert(cast<Function>(Target.getCallee()));
        for (CallInst *Call : Calls) {
            IRBuilder<> B(Call);
            auto *New=B.CreateCall(Target,{Call->getArgOperand(0),Call->getArgOperand(1)});
            New->setDebugLoc(Call->getDebugLoc());
            Call->replaceAllUsesWith(New); Call->eraseFromParent();
        }
    }
    if (Dso) {
        if (!Dso->use_empty()) report_fatal_error("ENCBound: unsupported SDK DSO handle access");
        Dso->eraseFromParent();
    }
}
