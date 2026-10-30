// Owner-authorized writable globals. Included inside the pass namespace.
// Table cells initially contain (radix << 59) + relocated raw slot address.
// Trusted startup replaces each cell with its capability, then applies fixups.
bool protectedGlobal(const GlobalVariable &G) {
    return !G.isConstant() && !G.getName().starts_with("llvm.") &&
           !G.getName().starts_with("__encbound_");
}

bool containsProtectedGlobal(Constant *C) {
    if (auto *G = dyn_cast<GlobalVariable>(C)) return protectedGlobal(*G);
    if (isa<GlobalValue>(C)) return false;
    for (Value *V : C->operands())
        if (auto *K = dyn_cast<Constant>(V); K && containsProtectedGlobal(K)) return true;
    return false;
}

struct GlobalTransform {
    DenseMap<GlobalVariable *, GlobalVariable *> Cells;
    SmallVector<GlobalVariable *, 32> Definitions;
    SmallPtrSet<CallInst *, 32> Accessors;

    void run(Module &M) {
        if (!ProtectedGlobalsOption) return;
        auto &C = M.getContext(); auto &DL = M.getDataLayout();
        auto *I64 = Type::getInt64Ty(C); auto *P = PointerType::get(C, 0);
        SmallVector<GlobalVariable *, 32> Inputs;
        for (GlobalVariable &G : M.globals()) {
            if (G.getName().starts_with("llvm.") || G.getSection() == ".encbound.abi") continue;
            if (G.isConstant() && G.hasInitializer() && containsProtectedGlobal(G.getInitializer()))
                report_fatal_error(Twine("ENCBound: read-only initializer references protected global: ") + G.getName());
            if (protectedGlobal(G)) Inputs.push_back(&G);
        }
        for (GlobalVariable *Old : Inputs) {
            bool ODR = CxxLifecycleOption && Old->hasComdat() &&
                Old->getComdat()->getSelectionKind()==Comdat::Any &&
                (Old->hasLinkOnceODRLinkage() || Old->hasWeakODRLinkage());
            if ((!ODR && (Old->hasComdat() || !(Old->hasExternalLinkage() || Old->hasLocalLinkage()))) ||
                Old->isExternallyInitialized() || Old->hasSection())
                report_fatal_error(Twine("ENCBound: unsupported protected global linkage/section: ") + Old->getName());
            auto *Cell = new GlobalVariable(M, I64, false, Old->getLinkage(), nullptr,
                                           "__encbound_gcap_" + Old->getName());
            Cell->setVisibility(Old->hasLocalLinkage() ? GlobalValue::DefaultVisibility : GlobalValue::HiddenVisibility);
            Cell->setDSOLocal(true); Cell->setAlignment(Align(8));
            if (ODR) Cell->setComdat(Old->getComdat());
            if (!Old->hasInitializer()) { Cells[Old] = Cell; continue; }
            uint64_t N = DL.getTypeAllocSize(Old->getValueType());
            uint64_t A = Old->getAlign().valueOrOne().value();
            A = std::max<uint64_t>(A, DL.getABITypeAlign(Old->getValueType()).value());
            uint64_t Need = std::max<uint64_t>({N, A, 2});
            if (!N || Need > (1ull << 30)) report_fatal_error("ENCBound: unsupported protected global size/alignment");
            uint64_t S = PowerOf2Ceil(Need);
            auto *Pad = ArrayType::get(Type::getInt8Ty(C), S-N);
            auto *T = StructType::get(C, {Old->getValueType(), Pad});
            auto *Init = ConstantStruct::get(T, {Old->getInitializer(), ConstantAggregateZero::get(Pad)});
            bool Zero = Init->isNullValue();
            auto *Storage = new GlobalVariable(M, T, false, Old->getLinkage(), Init);
            Storage->copyAttributesFrom(Old); Storage->takeName(Old);
            if (ODR) Storage->setComdat(Old->getComdat());
            Storage->setAlignment(Align(S));
            Storage->setSection(Zero ? ".encbound.globalbss" : ".encbound.globalrw");
            Old->replaceAllUsesWith(Storage); Old->eraseFromParent();
            auto *Address = ConstantExpr::getPtrToInt(Storage, I64);
            unsigned R = Log2_64(S);
            Cell->setInitializer(ConstantExpr::getAdd(Address, ConstantInt::get(I64, uint64_t(R) << 59)));
            Cell->setSection("encbound_gcaps");
            appendToUsed(M, {Storage, Cell}); Cells[Storage] = Cell;
            Definitions.push_back(Storage);
        }
        // Emit exact compiler-established relocation destinations, never scan data.
        for (GlobalVariable *G : Definitions) fixups(M, G, G->getInitializer(), 0);
        auto Get = M.getOrInsertFunction("encbound_global_cap", FunctionType::get(I64, {P}, false));
        for (Function &F : M) if (!F.isDeclaration()) {
            SmallVector<Instruction *, 64> Original;
            for (Instruction &I : instructions(F)) Original.push_back(&I);
            DenseMap<GlobalVariable *, Value *> Caps;
            for (Instruction *I : Original) {
                for (unsigned J = 0; J < I->getNumOperands(); ++J) {
                    auto *K = dyn_cast<Constant>(I->getOperand(J));
                    if (!K || !containsProtectedGlobal(K)) continue;
                    Instruction *At = I;
                    if (auto *Phi = dyn_cast<PHINode>(I)) At = Phi->getIncomingBlock(J)->getTerminator();
                    I->setOperand(J, materialize(M, K, At, F, Caps, Get));
                }
            }
        }
        auto *Mode = new GlobalVariable(M, I64, true, GlobalValue::InternalLinkage,
            ConstantInt::get(I64,1), "__encbound_globals_v1");
        Mode->setSection(".encbound.abi"); Mode->setAlignment(Align(8)); appendToUsed(M,{Mode});
    }

    void fixups(Module &M, GlobalVariable *Dst, Constant *K, uint64_t Offset) {
        if (!containsProtectedGlobal(K)) return;
        auto &DL = M.getDataLayout(); auto &C = M.getContext();
        if (K->getType()->isStructTy() || K->getType()->isArrayTy()) {
            auto *ST = dyn_cast<StructType>(K->getType());
            for (unsigned I=0; I<K->getNumOperands(); ++I) {
                uint64_t O = ST ? DL.getStructLayout(ST)->getElementOffset(I) :
                    I * DL.getTypeAllocSize(cast<ArrayType>(K->getType())->getElementType());
                fixups(M, Dst, cast<Constant>(K->getOperand(I)), Offset+O);
            }
            return;
        }
        if (!(K->getType()->isPointerTy() || K->getType()->isIntegerTy(64)))
            report_fatal_error("ENCBound: unsupported protected global initializer representation");
        APInt Addend(64, 0); Constant *Base = K;
        while (auto *E = dyn_cast<ConstantExpr>(Base)) {
            if (E->getOpcode() == Instruction::GetElementPtr) {
                if (!cast<GEPOperator>(E)->accumulateConstantOffset(DL, Addend))
                    report_fatal_error("ENCBound: nonconstant global initializer offset");
            } else if (E->getOpcode() != Instruction::BitCast && E->getOpcode() != Instruction::PtrToInt)
                report_fatal_error("ENCBound: unsupported protected global initializer expression");
            Base = cast<Constant>(E->getOperand(0));
        }
        auto *Target = dyn_cast<GlobalVariable>(Base);
        if (!Target || !Cells.count(Target)) report_fatal_error("ENCBound: unresolved protected global initializer");
        auto *I64=Type::getInt64Ty(C); auto *P=PointerType::get(C,0);
        auto *T=StructType::get(C,{P,P,I64});
        auto *Dest=ConstantExpr::getGetElementPtr(Type::getInt8Ty(C),Dst,ConstantInt::get(I64,Offset));
        auto *Init=ConstantStruct::get(T,{Dest,Cells[Target],ConstantInt::get(C,Addend)});
        auto *Record=new GlobalVariable(M,T,true,GlobalValue::PrivateLinkage,Init,"__encbound_global_fixup");
        Record->setSection("encbound_gfix"); Record->setAlignment(Align(8)); appendToUsed(M,{Record});
        if (Dst->hasComdat()) Record->setComdat(Dst->getComdat());
    }

    Value *materialize(Module &M, Constant *K, Instruction *At, Function &F,
                       DenseMap<GlobalVariable *, Value *> &Caps, FunctionCallee Get) {
        if (!containsProtectedGlobal(K)) return K;
        if (auto *G=dyn_cast<GlobalVariable>(K)) {
            if (Caps.count(G)) return Caps[G];
            IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
            auto *Call=B.CreateCall(Get,{Cells.lookup(G)},"encbound.global.cap"); Accessors.insert(Call);
            return Caps[G]=B.CreateIntToPtr(Call,K->getType());
        }
        if (auto *E=dyn_cast<ConstantExpr>(K)) {
            Instruction *I=E->getAsInstruction(); I->insertBefore(At->getIterator());
            for (unsigned J=0; J<I->getNumOperands(); ++J)
                I->setOperand(J,materialize(M,cast<Constant>(I->getOperand(J)),I,F,Caps,Get));
            return I;
        }
        if (K->getType()->isStructTy() || K->getType()->isArrayTy()) {
            IRBuilder<> B(At); Value *V=PoisonValue::get(K->getType());
            for (unsigned J=0; J<K->getNumOperands(); ++J)
                V=B.CreateInsertValue(V,materialize(M,cast<Constant>(K->getOperand(J)),At,F,Caps,Get),{J});
            return V;
        }
        report_fatal_error("ENCBound: unsupported protected global reference expression");
    }
};
