// ENCBound x86-64 SysV scalar call-frame extension to LLVM ExpandVariadics.
// Included inside the adapted upstream implementation's anonymous namespace.
struct X86SysV final : VariadicABIInfo {
  bool enableForTarget() override { return true; }
  bool vaListPassedInSSARegister() override { return false; }
  Type *vaListType(LLVMContext &C) override {
    return StructType::get(C, {Type::getInt32Ty(C), Type::getInt32Ty(C),
                              PointerType::getUnqual(C), PointerType::getUnqual(C)});
  }
  Type *vaListParameterType(Module &M) override {
    return PointerType::getUnqual(M.getContext());
  }
  Value *initializeVaList(Module &, LLVMContext &, IRBuilder<> &,
                          AllocaInst *, Value *) override {
    llvm_unreachable("x86 uses the call-wide frame hook");
  }
  VAArgSlotInfo slotInfo(const DataLayout &, Type *) override {
    llvm_unreachable("x86 uses the call-wide frame hook");
  }
  bool hasCustomCallFrame() const override { return true; }

  Value *createCallFrame(Module &M, IRBuilder<> &B, const CallBase &Call,
                         const FunctionType &Original) override {
    struct Location { Value *V; bool Register; uint64_t Offset; };
    SmallVector<Location, 16> Locations;
    unsigned GP = 0, FP = 0, InitialGP = 0, InitialFP = 48;
    uint64_t OverflowSize = 0;
    for (unsigned I = 0; I < Call.arg_size(); ++I) {
      Value *V = Call.getArgOperand(I);
      Type *T = V->getType();
      const bool Floating = T->isDoubleTy();
      if (!(Floating || (T->isIntegerTy() && T->getIntegerBitWidth() <= 64) ||
            (T->isPointerTy() && T->getPointerAddressSpace() == 0)))
        report_fatal_error("ENCBound: unsupported x86 variadic argument type");
      bool Register = Floating ? FP < 8 : GP < 6;
      uint64_t Offset = Floating ? 48 + 16 * FP : 8 * GP;
      if (Register) { if (Floating) ++FP; else ++GP; }
      if (I < Original.getNumParams()) {
        InitialGP = 8 * GP; InitialFP = 48 + 16 * FP;
        continue;
      }
      if (!Register) { Offset = OverflowSize; OverflowSize += 8; }
      Locations.push_back({V, Register, Offset});
    }

    // Entry allocas have constant sizes even when the call is inside a loop.
    // Reinitialize at each execution of the call; va_copy shares these areas.
    auto &C = M.getContext();
    Function *Caller = const_cast<Function *>(Call.getFunction());
    B.SetInsertPointPastAllocas(Caller);
    // The shared builder can retain a location from a different function.
    // Entry insertion does not select this call's inline scope automatically.
    B.SetCurrentDebugLocation(Call.getStableDebugLoc());
    auto Allocate = [&](Type *T, StringRef Name, Align A) {
      AllocaInst *P = B.CreateAlloca(T, nullptr, Name);
      P->setAlignment(A); return P;
    };
    auto *Regs = Allocate(ArrayType::get(B.getInt8Ty(), 176), "encbound.va.regs", Align(16));
    // An empty overflow image is owned zeroed storage, never a native stack
    // pointer. This adds no exact argument-count/type-safety claim.
    uint64_t ReservedOverflow = std::max<uint64_t>(OverflowSize, 8);
    auto *Overflow = Allocate(ArrayType::get(B.getInt8Ty(), ReservedOverflow), "encbound.va.overflow", Align(8));
    auto *Descriptor = Allocate(vaListType(C), "encbound.va.initial", Align(8));
    B.SetInsertPoint(const_cast<CallBase *>(&Call));
    B.CreateMemSet(Regs, B.getInt8(0), 176, Align(16));
    B.CreateMemSet(Overflow, B.getInt8(0), ReservedOverflow, Align(8));
    for (auto L : Locations) {
      Value *Address = B.CreateGEP(B.getInt8Ty(), L.Register ? Regs : Overflow,
                                   B.getInt64(L.Offset), "encbound.va.slot");
      B.CreateAlignedStore(L.V, Address, Align(8));
    }
    Type *DescriptorType = vaListType(C);
    Value *Fields[] = {B.getInt32(InitialGP), B.getInt32(InitialFP), Overflow, Regs};
    for (unsigned I = 0; I < 4; ++I)
      B.CreateStore(Fields[I], B.CreateStructGEP(DescriptorType, Descriptor, I));
    return Descriptor;
  }
};
