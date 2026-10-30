// Included inside the pass implementation's anonymous namespace. No public ABI.
cl::opt<std::string> FastPathsOption("encbound-fast-paths",cl::init("off"),
    cl::desc("Late guarded lowering: off, inline, loops"),cl::Hidden);

[[noreturn]] void fastFail(const char *Why) {
    report_fatal_error(Twine("ENCBound: fast-path validation failed: ")+Why);
}
void fastNeed(bool Good,const char *Why) { if (!Good) fastFail(Why); }
using FastBuilder = IRBuilder<NoFolder>;

bool spanSingle(CallInst *C) {
    if (!C || !namedCall(*C,"encbound_span_require") || C->arg_size()!=5 || !C->hasOneUse()) return false;
    auto *W=dyn_cast<ConstantInt>(C->getArgOperand(1));
    auto *K=dyn_cast<ConstantInt>(C->getArgOperand(2));
    auto *P=dyn_cast<IntToPtrInst>(*C->user_begin());
    auto *A=P && P->hasOneUse() ? dyn_cast<Instruction>(*P->user_begin()) : nullptr;
    uint64_t Bytes=0; unsigned Kind=0;
    return W && K && A && scalarProofAccess(A,P,Bytes,Kind) &&
        Bytes==W->getZExtValue() && Kind==K->getZExtValue() && C->getParent()==A->getParent();
}
struct SlotGeometry { Value *Start,*Size; };
SlotGeometry slotGeometry(FastBuilder &B,Value *Anchor) {
    Value *R=B.CreateLShr(Anchor,B.getInt64(59),"encbound.fast.radix");
    Value *Size=B.CreateShl(B.getInt64(1),R,"encbound.fast.size"); // radix <=31
    Value *Mask=B.CreateNot(B.CreateSub(Size,B.getInt64(1)),"encbound.fast.mask");
    return {B.CreateAnd(Anchor,Mask,"encbound.fast.start"),Size};
}
Value *spanCondition(FastBuilder &B,CallInst *C,SlotGeometry G) {
    Value *Delta=B.CreateSub(C->getArgOperand(0),G.Start,"encbound.fast.delta");
    Value *Room=B.CreateSub(G.Size,C->getArgOperand(1));
    return B.CreateAnd(B.CreateICmpNE(C->getArgOperand(4),B.getInt64(0)),
        B.CreateAnd(B.CreateICmpULE(C->getArgOperand(1),G.Size),B.CreateICmpULE(Delta,Room)),
        "encbound.fast.ok");
}
// Independent structural comparison of a regenerated predicate/offset tree.
// Exact existing leaves must match by identity. Only pure address computations
// may differ by instruction identity; flags, predicates, types and operands agree.
bool sameFastExpr(Value *A,Value *B,unsigned Depth=0) {
    if (A==B) return true;
    if (Depth>96) return false;
    auto *X=dyn_cast<Instruction>(A); auto *Y=dyn_cast<Instruction>(B);
    if (!X || !Y || !(isa<BinaryOperator>(X)||isa<ICmpInst>(X)||isa<CastInst>(X)||isa<GetElementPtrInst>(X)) ||
        !X->isSameOperationAs(Y) || !X->hasSameSubclassOptionalData(Y) || X->getNumOperands()!=Y->getNumOperands()) return false;
    for (unsigned I=0;I<X->getNumOperands();++I)
        if (!sameFastExpr(X->getOperand(I),Y->getOperand(I),Depth+1)) return false;
    return true;
}
void deadFastCleanup(Function &F) {
    bool Changed;
    do {
        Changed=false;
        for (BasicBlock &B:F) for (auto I=B.begin();I!=B.end();) {
            Instruction *V=&*I++;
            // Re-abstraction may discard regenerated arithmetic, never a memory
            // operation: even an unused unauthorized load must reach the verifier.
            if (!V->isTerminator() && !isa<CallBase>(V) && !V->mayReadOrWriteMemory() &&
                isInstructionTriviallyDead(V)) {
                V->eraseFromParent();Changed=true;
            }
        }
    } while(Changed);
}
// Inline hit/fallback diamond. Slot geometry is placed directly after its
// already verified preparation; the actual guard/fallback stays at the access.
void inlineSpans(Function &F) {
    SmallVector<CallInst *,32> Calls;
    DenseMap<Value *,SlotGeometry> Geometry;
    for (Instruction &I:instructions(F)) if (auto *C=dyn_cast<CallInst>(&I))
        if (spanSingle(C)) Calls.push_back(C);
    for (CallInst *C:Calls) {
        auto *Prepare=dyn_cast<CallInst>(C->getArgOperand(4));
        if (!Prepare || !namedCall(*Prepare,"encbound_span_prepare")) continue;
        SlotGeometry G;
        auto It=Geometry.find(Prepare);
        if (It==Geometry.end()) {
            FastBuilder B(Prepare->getNextNode());G=slotGeometry(B,C->getArgOperand(3));Geometry[Prepare]=G;
        } else G=It->second;
        BasicBlock *Head=C->getParent();
        BasicBlock *Join=Head->splitBasicBlock(C->getIterator(),"encbound.inline.join");
        Head->getTerminator()->eraseFromParent();
        BasicBlock *Hit=BasicBlock::Create(F.getContext(),"encbound.inline.hit",&F,Join);
        BasicBlock *Miss=BasicBlock::Create(F.getContext(),"encbound.inline.miss",&F,Join);
        FastBuilder B(Head);
        Value *OK=spanCondition(B,C,G);B.CreateCondBr(OK,Hit,Miss);
        B.SetInsertPoint(Hit);
        Value *Raw=B.CreateAdd(C->getArgOperand(4),B.CreateSub(C->getArgOperand(0),G.Start),"encbound.inline.raw");
        B.CreateBr(Join);
        C->removeFromParent();C->insertInto(Miss,Miss->end());
        B.SetInsertPoint(Miss);B.CreateBr(Join);
        B.SetInsertPoint(&*Join->begin());
        auto *P=B.CreatePHI(B.getInt64Ty(),2,"encbound.inline.result");
        C->replaceAllUsesWith(P);P->addIncoming(Raw,Hit);P->addIncoming(C,Miss);
        P->setMetadata("encbound.inline",MDNode::get(F.getContext(),{}));
    }
}
// Re-abstract one exact diamond. Its sole fallback producer remains a real
// span_require; the existing verifier will validate that producer and token.
void abstractInline(PHINode *P) {
    fastNeed(P->getNumIncomingValues()==2,"inline PHI arity");
    auto *C=dyn_cast<CallInst>(P->getIncomingValue(1));
    fastNeed(C && namedCall(*C,"encbound_span_require") && C->arg_size()==5 && C->hasOneUse(),"inline fallback");
    BasicBlock *Join=P->getParent(),*Hit=P->getIncomingBlock(0),*Miss=P->getIncomingBlock(1);
    BasicBlock *Head=Hit->getSinglePredecessor();
    fastNeed(Head && Miss->getSinglePredecessor()==Head && C->getParent()==Miss &&
        pred_size(Join)==2 && Hit->getSingleSuccessor()==Join && Miss->getSingleSuccessor()==Join,"inline edges");
    auto *BR=dyn_cast<BranchInst>(Head->getTerminator());
    fastNeed(BR && BR->isConditional() && BR->getSuccessor(0)==Hit && BR->getSuccessor(1)==Miss,"inline branch");
    // Miss has exactly one call; Hit only has the two integer address operations.
    fastNeed(Miss->size()==2 && Hit->size()==3 && &*Miss->begin()==C,"inline body");
    auto *W=dyn_cast<ConstantInt>(C->getArgOperand(1));auto *K=dyn_cast<ConstantInt>(C->getArgOperand(2));
    fastNeed(W && W->getZExtValue() && K && (K->equalsInt(1)||K->equalsInt(2)),"inline access ABI");
    FastBuilder B(BR);
    SlotGeometry G=slotGeometry(B,C->getArgOperand(3));
    Value *OK=spanCondition(B,C,G);
    Value *Raw=B.CreateAdd(C->getArgOperand(4),B.CreateSub(C->getArgOperand(0),G.Start));
    fastNeed(sameFastExpr(BR->getCondition(),OK) && sameFastExpr(P->getIncomingValue(0),Raw),"inline predicate/raw mismatch");
    // Any extra escape of fast raw/offset survives removal and makes erasure
    // invalid; check all uses before dropping this verified pair of operations.
    auto *Add=dyn_cast<BinaryOperator>(P->getIncomingValue(0));
    fastNeed(Add && Add->hasOneUse(),"inline raw escape");
    auto *Delta=dyn_cast<BinaryOperator>(Add->getOperand(1));
    fastNeed(Delta && Delta->hasOneUse() && Delta->getParent()==Hit && Add->getParent()==Hit,"inline delta escape");
    P->replaceAllUsesWith(C);P->eraseFromParent();
    C->moveBefore(BR->getIterator());BR->eraseFromParent();BranchInst::Create(Join,Head);
    Hit->dropAllReferences();Miss->dropAllReferences();Hit->eraseFromParent();Miss->eraseFromParent();
    fastNeed(MergeBlockIntoPredecessor(Join),"inline join merge");
    deadFastCleanup(*Head->getParent());
}

struct LoopShape {
    BasicBlock *Body,*Entry,*Exit; PHINode *IV; Value *Start,*End; uint64_t Step;
    SmallVector<CallInst *,16> Checks;
};
bool loopShape(BasicBlock *Body,LoopShape &S) {
    auto *BR=dyn_cast<BranchInst>(Body->getTerminator());
    if (!BR || !BR->isConditional()) return false;
    auto *Cmp=dyn_cast<ICmpInst>(BR->getCondition());
    if (!Cmp || (Cmp->getPredicate()!=ICmpInst::ICMP_EQ && Cmp->getPredicate()!=ICmpInst::ICMP_NE)) return false;
    unsigned Back=Cmp->getPredicate()==ICmpInst::ICMP_EQ ? 1:0;
    if (BR->getSuccessor(Back)!=Body || BR->getSuccessor(1-Back)==Body) return false;
    BasicBlock *Entry=nullptr;
    for (BasicBlock *P:predecessors(Body)) if (P!=Body) {if(Entry)return false;Entry=P;}
    if (!Entry || Entry->getSingleSuccessor()!=Body) return false;
    PHINode *IV=nullptr;Value *End=nullptr;uint64_t Step=0;
    for (unsigned Side=0;Side<2;++Side) {
        auto *Inc=dyn_cast<BinaryOperator>(Cmp->getOperand(Side));
        if (!Inc || Inc->getOpcode()!=Instruction::Add || Inc->getParent()!=Body || !Inc->getType()->isIntegerTy(64)) continue;
        auto *P=dyn_cast<PHINode>(Inc->getOperand(0));auto *K=dyn_cast<ConstantInt>(Inc->getOperand(1));
        if (!P || P->getParent()!=Body || !K || !K->getZExtValue() || K->getZExtValue()>(1ull<<30) ||
            P->getNumIncomingValues()!=2 || P->getIncomingValueForBlock(Body)!=Inc) continue;
        auto *E=dyn_cast<Instruction>(Cmp->getOperand(1-Side));
        if (E && E->getParent()==Body) continue;
        IV=P;End=Cmp->getOperand(1-Side);Step=K->getZExtValue();break;
    }
    if (!IV) return false;
    S={Body,Entry,BR->getSuccessor(1-Back),IV,IV->getIncomingValueForBlock(Entry),End,Step,{}};
    for (Instruction &I:*Body) {
        if (spanBarrier(I)) return false;
        if (auto *C=dyn_cast<CallInst>(&I)) {
            if (!spanSingle(C)) return false;
            auto *P=dyn_cast<Instruction>(C->getArgOperand(4));
            auto *A=dyn_cast<Instruction>(C->getArgOperand(3));
            if (!P || P->getParent()==Body || (A && A->getParent()==Body)) return false;
            S.Checks.push_back(C);
        }
        for (User *U:I.users()) if (auto *Use=dyn_cast<Instruction>(U))
            if (Use->getParent()!=Body && !(isa<PHINode>(Use)&&Use->getParent()==S.Exit)) return false;
    }
    return !S.Checks.empty();
}
// Reconstruct the capability expression at the first iteration and its constant
// nonnegative byte stride. GEP offsets use DataLayout without trusting flags.
bool affineFirst(Value *V,LoopShape &S,FastBuilder &B,Value *&First,uint64_t &Stride,unsigned Depth=0) {
    if (Depth>48) return false;
    if (V==S.IV) {First=S.Start;Stride=1;return true;}
    auto *I=dyn_cast<Instruction>(V);
    if (!I || I->getParent()!=S.Body) {First=V;Stride=0;return true;}
    if (auto *G=dyn_cast<GetElementPtrInst>(I)) {
        Value *Base=nullptr;
        if (!affineFirst(G->getPointerOperand(),S,B,Base,Stride,Depth+1)) return false;
        SmallVector<Value *,8> Indices;
        DenseMap<Value *,uint64_t> IndexStrides;
        for (Value *Index:G->indices()) {
            Value *Initial=nullptr; uint64_t D=0;
            if (!affineFirst(Index,S,B,Initial,D,Depth+1) ||
                (D && !Index->getType()->isIntegerTy(64))) return false;
            Indices.push_back(Initial); IndexStrides[Index]=D;
        }
        SmallMapVector<Value *,APInt,4> Terms; APInt Constant(64,0);
        if (!G->collectOffset(G->getModule()->getDataLayout(),64,Terms,Constant)) return false;
        for (auto &Term:Terms) {
            uint64_t D=IndexStrides.lookup(Term.first);
            uint64_t Scale=Term.second.getZExtValue();
            if (!Scale) continue;
            if (D && (Scale>(1ull<<30) || D>((1ull<<30)-Stride)/Scale)) return false;
            Stride+=D*Scale;
        }
        First=B.CreateGEP(G->getSourceElementType(),Base,Indices);
        return true;
    }
    if ((isa<PtrToIntInst>(I) && I->getType()->isIntegerTy(64)) ||
        (isa<IntToPtrInst>(I) && I->getOperand(0)->getType()->isIntegerTy(64))) {
        Value *X=nullptr;if(!affineFirst(I->getOperand(0),S,B,X,Stride,Depth+1))return false;
        First=isa<PtrToIntInst>(I) ? B.CreatePtrToInt(X,I->getType()):B.CreateIntToPtr(X,I->getType());return true;
    }
    auto *Op=dyn_cast<BinaryOperator>(I);
    if (!Op || !Op->getType()->isIntegerTy(64)) return false;
    Value *X=nullptr,*Y=nullptr;uint64_t DX=0,DY=0;
    if (!affineFirst(Op->getOperand(0),S,B,X,DX,Depth+1)||!affineFirst(Op->getOperand(1),S,B,Y,DY,Depth+1))return false;
    if (Op->getOpcode()==Instruction::Add) {
        if (DX>(1ull<<30)-DY)return false;
        Stride=DX+DY;First=B.CreateAdd(X,Y);return true;
    }
    if (Op->getOpcode()==Instruction::Mul) {
        if (!DX&&!DY) {Stride=0;First=B.CreateMul(X,Y);return true;}
        auto *K=dyn_cast<ConstantInt>(DX ? Y:X);uint64_t D=DX?DX:DY;
        if ((DX&&DY)||!K||K->getZExtValue()>(1ull<<30)/D)return false;
        Stride=D*K->getZExtValue();First=B.CreateMul(X,Y);return true;
    }
    if (Op->getOpcode()==Instruction::Shl) {
        auto *K=dyn_cast<ConstantInt>(Y);
        if (!K || K->getZExtValue()>30 || DX>((1ull<<30)>>K->getZExtValue()))return false;
        Stride=DX<<K->getZExtValue();First=B.CreateShl(X,Y);return true;
    }
    return false;
}
Value *loopCondition(LoopShape &S,FastBuilder &B) {
    Value *Distance=B.CreateSub(S.End,S.Start);
    Value *Count=B.CreateUDiv(Distance,B.getInt64(S.Step));
    Value *OK=B.CreateAnd(B.CreateICmpUGT(S.End,S.Start),
        B.CreateICmpEQ(B.CreateURem(Distance,B.getInt64(S.Step)),B.getInt64(0)));
    for (CallInst *C:S.Checks) {
        Value *First=nullptr;uint64_t Stride=0;
        if (!affineFirst(C->getArgOperand(0),S,B,First,Stride) || Stride>(1ull<<30)/S.Step) return nullptr;
        auto G=slotGeometry(B,C->getArgOperand(3));
        Value *Delta=B.CreateSub(First,G.Start);
        Value *Room=B.CreateSub(G.Size,C->getArgOperand(1));
        Value *Range=B.CreateAnd(B.CreateICmpNE(C->getArgOperand(4),B.getInt64(0)),
            B.CreateAnd(B.CreateICmpULE(C->getArgOperand(1),G.Size),B.CreateICmpULE(Delta,Room)));
        if (Stride) Range=B.CreateAnd(Range,B.CreateICmpULE(B.CreateSub(Count,B.getInt64(1)),
            B.CreateUDiv(B.CreateSub(Room,Delta),B.getInt64(Stride*S.Step))));
        OK=B.CreateAnd(OK,Range);
    }
    return OK;
}
void versionLoops(Function &F) {
    SmallVector<BasicBlock *,16> Bodies;
    for (BasicBlock &B:F) {LoopShape S;if(loopShape(&B,S))Bodies.push_back(&B);}
    for (BasicBlock *Body:Bodies) {
        LoopShape S;if(!loopShape(Body,S))continue;
        auto *Old=S.Entry->getTerminator();FastBuilder B(Old);
        Value *OK=loopCondition(S,B);if(!OK){deadFastCleanup(F);continue;}
        ValueToValueMapTy Map;
        BasicBlock *Fast=CloneBasicBlock(Body,Map,".encbound.fast",&F);
        Map[Body]=Fast;
        for (Instruction &I:*Fast) RemapInstruction(&I,Map,RF_NoModuleLevelChanges|RF_IgnoreMissingLocals);
        BasicBlock *Hit=BasicBlock::Create(F.getContext(),"encbound.loop.hit",&F,Fast);
        BasicBlock *Miss=BasicBlock::Create(F.getContext(),"encbound.loop.miss",&F,Body);
        BranchInst::Create(Fast,Hit);BranchInst::Create(Body,Miss);
        for (PHINode &P:Body->phis()) P.setIncomingBlock(P.getBasicBlockIndex(S.Entry),Miss);
        for (PHINode &P:Fast->phis()) P.setIncomingBlock(P.getBasicBlockIndex(S.Entry),Hit);
        for (PHINode &P:S.Exit->phis()) {
            int Index=P.getBasicBlockIndex(Body);if(Index<0)continue;
            Value *V=P.getIncomingValue(Index);auto It=Map.find(V);
            P.addIncoming(It==Map.end()?V:static_cast<Value *>(It->second),Fast);
        }
        for (CallInst *C:S.Checks) {
            auto *Copy=cast<CallInst>(Map[C]);FastBuilder CB(Copy);
            // Invariant geometry at the dispatch, dynamic delta at the access.
            auto G=slotGeometry(B,C->getArgOperand(3));
            Value *Raw=CB.CreateAdd(Copy->getArgOperand(4),CB.CreateSub(Copy->getArgOperand(0),G.Start),"encbound.loop.raw");
            Copy->replaceAllUsesWith(Raw);Copy->eraseFromParent();
        }
        auto *Gate=BranchInst::Create(Hit,Miss,OK,Old->getIterator());Old->eraseFromParent();
        Gate->setMetadata("encbound.loop",MDNode::get(F.getContext(),{}));
    }
}
// Compare the fast copy to the actual original loop. Only replacing its span
// calls by token+(identical capability-slot start) is permitted.
void abstractLoop(BranchInst *Gate) {
    fastNeed(Gate->isConditional(),"loop dispatch");
    BasicBlock *Hit=Gate->getSuccessor(0),*Miss=Gate->getSuccessor(1),*Entry=Gate->getParent();
    fastNeed(Hit->size()==1 && Miss->size()==1 && Hit->getSinglePredecessor()==Entry && Miss->getSinglePredecessor()==Entry,"loop entries");
    BasicBlock *Fast=Hit->getSingleSuccessor(),*Slow=Miss->getSingleSuccessor();
    fastNeed(Fast && Slow && Fast!=Slow,"loop copies");
    LoopShape S;fastNeed(loopShape(Slow,S) && S.Entry==Miss,"original loop shape");
    FastBuilder B(Gate);Value *OK=loopCondition(S,B);
    fastNeed(OK && sameFastExpr(Gate->getCondition(),OK),"loop range predicate");
    DenseMap<Value *,Value *> Map;Map[Slow]=Fast;Map[Miss]=Hit;
    auto FI=Fast->begin();
    for (Instruction &I:*Slow) {
        fastNeed(FI!=Fast->end(),"short fast loop");
        if (namedCall(I,"encbound_span_require")) {
            auto *C=cast<CallInst>(&I);
            auto *Delta=dyn_cast<BinaryOperator>(&*FI++);
            fastNeed(FI!=Fast->end(),"missing fast raw");
            auto *Raw=dyn_cast<BinaryOperator>(&*FI++);
            fastNeed(Delta && Raw && Delta->getOpcode()==Instruction::Sub && Raw->getOpcode()==Instruction::Add &&
                !Delta->hasNoUnsignedWrap()&&!Delta->hasNoSignedWrap()&&!Raw->hasNoUnsignedWrap()&&!Raw->hasNoSignedWrap(),"loop raw operations");
            auto Mapped=[&](Value *V)->Value* {auto It=Map.find(V);return It==Map.end()?V:It->second;};
            auto G=slotGeometry(B,C->getArgOperand(3));
            fastNeed(Delta->getOperand(0)==Mapped(C->getArgOperand(0)) && sameFastExpr(Delta->getOperand(1),G.Start) &&
                Raw->getOperand(0)==C->getArgOperand(4) && Raw->getOperand(1)==Delta && Delta->hasOneUse() && Raw->hasOneUse(),"loop raw mismatch/escape");
            Map[C]=Raw;
        } else {Map[&I]=&*FI++;}
    }
    fastNeed(FI==Fast->end(),"extra fast-loop instructions");
    for (Instruction &I:*Slow) {
        if (namedCall(I,"encbound_span_require")) continue;
        auto *J=cast<Instruction>(Map[&I]);
        fastNeed(I.isSameOperationAs(J) && I.hasSameSubclassOptionalData(J) && I.getNumOperands()==J->getNumOperands(),"loop instruction differs");
        for (unsigned N=0;N<I.getNumOperands();++N) {
            Value *V=I.getOperand(N);auto It=Map.find(V);
            fastNeed(J->getOperand(N)==(It==Map.end()?V:It->second),"loop operand differs");
        }
        if(auto *P=dyn_cast<PHINode>(&I)) {
            auto *Q=cast<PHINode>(J);
            for(unsigned N=0;N<P->getNumIncomingValues();++N) {
                auto *BB=P->getIncomingBlock(N);auto It=Map.find(BB);
                fastNeed(Q->getIncomingBlock(N)==(It==Map.end()?BB:It->second),"loop PHI edge differs");
            }
        }
    }
    // Every external use of a copied value must be an identical exit PHI arm.
    for(Instruction &I:*Fast) for(User *U:I.users()) if(auto *J=dyn_cast<Instruction>(U)) {
        if(J->getParent()==Fast)continue;
        auto *P=dyn_cast<PHINode>(J);
        fastNeed(P && P->getParent()==S.Exit && P->getBasicBlockIndex(Fast)>=0 && P->getBasicBlockIndex(Slow)>=0,"fast value escape");
        Value *Original=P->getIncomingValueForBlock(Slow);auto It=Map.find(Original);
        fastNeed(It!=Map.end() && P->getIncomingValueForBlock(Fast)==It->second,"exit value differs");
    }
    for(PHINode &P:S.Exit->phis()) if(P.getBasicBlockIndex(Fast)>=0) {
        fastNeed(P.getBasicBlockIndex(Slow)>=0,"missing slow exit arm");
        Value *V=P.getIncomingValueForBlock(Slow);auto It=Map.find(V);
        fastNeed(P.getIncomingValueForBlock(Fast)==(It==Map.end()?V:It->second),"exit PHI mismatch");
        P.removeIncomingValue(Fast,false);
    }
    for(PHINode &P:Slow->phis())P.setIncomingBlock(P.getBasicBlockIndex(Miss),Entry);
    Gate->eraseFromParent();BranchInst::Create(Slow,Entry);
    Fast->dropAllReferences();Hit->dropAllReferences();Miss->dropAllReferences();
    Fast->eraseFromParent();Hit->eraseFromParent();Miss->eraseFromParent();deadFastCleanup(*Entry->getParent());
}
struct ENCBoundFastVerifyPass:PassInfoMixin<ENCBoundFastVerifyPass> {
    PreservedAnalyses run(Module &M,ModuleAnalysisManager &) {
        fastNeed(!verifyModule(M,&errs()),"LLVM invalid input");
        auto Abstract=CloneModule(M);
        for(Function &F:*Abstract) {
            SmallVector<PHINode *,64> Inline;
            for(Instruction &I:instructions(F)) if(I.getMetadata("encbound.inline")) {
                auto *P=dyn_cast<PHINode>(&I);fastNeed(P,"inline marker on non-PHI");Inline.push_back(P);
            }
            // Reverse order: restore scope chains without invalidating later PHIs.
            for(auto I=Inline.rbegin();I!=Inline.rend();++I)abstractInline(*I);
            SmallVector<BranchInst *,16> Loops;
            for(Instruction &I:instructions(F)) if(I.getMetadata("encbound.loop")) {
                auto *B=dyn_cast<BranchInst>(&I);fastNeed(B,"loop marker on non-branch");Loops.push_back(B);
            }
            for(auto I=Loops.rbegin();I!=Loops.rend();++I)abstractLoop(*I);
        }
        fastNeed(!verifyModule(*Abstract,&errs()),"invalid re-abstraction");
        LoopAnalysisManager LAM;FunctionAnalysisManager FAM;CGSCCAnalysisManager CGAM;ModuleAnalysisManager AM;
        PassBuilder PB;PB.registerModuleAnalyses(AM);PB.registerCGSCCAnalyses(CGAM);PB.registerFunctionAnalyses(FAM);PB.registerLoopAnalyses(LAM);
        PB.crossRegisterProxies(LAM,FAM,CGAM,AM);
        ENCBoundVerifyPass().run(*Abstract,AM);
        return PreservedAnalyses::all();
    }
    static bool isRequired(){return true;}
};
struct ENCBoundFastPass:PassInfoMixin<ENCBoundFastPass> {
    PreservedAnalyses run(Module &M,ModuleAnalysisManager &) {
        if(FastPathsOption!="off"&&FastPathsOption!="inline"&&FastPathsOption!="loops")fastFail("unknown mode");
        if(FastPathsOption=="off")return PreservedAnalyses::all();
        if(CxxEHOption)fastFail("EH optimization combination is not validated");
        for(Function &F:M) if(!F.isDeclaration()) {
            if(FastPathsOption=="loops")versionLoops(F);
            inlineSpans(F);
        }
        return PreservedAnalyses::none();
    }
    static bool isRequired(){return true;}
};
