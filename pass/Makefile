#
# ENCBound restart - step 4 LLVM 21 pass plugin and IR tests.
#
# Run as: make -C pass test
#

LLVM_CONFIG ?= llvm-config-21
CLANG ?= clang-21
OPT ?= opt-21
CXX := clang++-21

ROOT := $(abspath $(CURDIR)/..)
BUILD := $(ROOT)/build/pass
SAMPLES := $(ROOT)/tests/pass
PLUGIN := $(BUILD)/encbound_pass.so

CXXFLAGS := $(shell $(LLVM_CONFIG) --cxxflags) -fPIC -Wall

.PHONY: all test clean

all: $(PLUGIN)

$(PLUGIN): $(CURDIR)/encbound_globals.h $(CURDIR)/encbound_lifecycle.h $(CURDIR)/encbound_vla.h $(CURDIR)/encbound_cxx_eh.h

$(BUILD):
	mkdir -p $@

$(PLUGIN): $(CURDIR)/encbound_pass.cpp $(CURDIR)/encbound_fast_paths.h $(CURDIR)/encbound_integration.h $(CURDIR)/encbound_variadics.h $(CURDIR)/encbound_x86_variadics.h $(CURDIR)/upstream/ExpandVariadics.cpp $(CURDIR)/Makefile | $(BUILD)
	$(CXX) $(CXXFLAGS) -shared $< $(CURDIR)/upstream/ExpandVariadics.cpp -o $@
	@echo "PASS PLUGIN => $@"

test: $(PLUGIN)
	python3 $(ROOT)/tests/vla/admission.py
	python3 $(SAMPLES)/variadics_test.py
	python3 $(ROOT)/tests/variadic-callbacks/run.py --native-only
	python3 $(SAMPLES)/atomic_virtual_test.py
	python3 $(SAMPLES)/fast_paths_test.py
	python3 $(SAMPLES)/local_proofs_test.py
	python3 $(SAMPLES)/reuse_test.py
	python3 $(SAMPLES)/admission_test.py
	python3 $(SAMPLES)/saturating_intrinsic_test.py
	python3 $(SAMPLES)/funnel_intrinsic_test.py
	python3 $(SAMPLES)/umul_intrinsic_test.py
	python3 $(SAMPLES)/floating_intrinsic_test.py
	python3 $(SAMPLES)/juliet_calls_test.py
	python3 $(SAMPLES)/capability_semantics_test.py
	python3 $(SAMPLES)/gep_policy_test.py
	python3 $(SAMPLES)/codegen_test.py
	$(CLANG) -O0 -Xclang -disable-O0-optnone -S -emit-llvm \
	    $(SAMPLES)/sample.c -o $(BUILD)/sample.ll
	$(OPT) -load-pass-plugin=$(PLUGIN) -passes=encbound -S \
	    $(BUILD)/sample.ll -o $(BUILD)/sample.inst.ll
	@n=$$(grep -c 'call i64 @encbound_require' $(BUILD)/sample.inst.ll); \
	 echo "instrumented checks: $$n"; test $$n -ge 4
	@if grep -q 'encbound.mem.nonzero' $(BUILD)/sample.inst.ll && \
	    grep -q 'encbound.mem.cont' $(BUILD)/sample.inst.ll; then \
	    echo "zero-length memory guard emitted"; \
	 else echo "FAIL: zero-length guard missing"; exit 1; fi
	@g=$$(grep -c 'call i64 @encbound_stack_mint' $(BUILD)/sample.inst.ll); \
	 echo "stack mints: $$g"; test $$g -ge 1
	@m=$$(grep -cE 'call.*@encbound_malloc\(' $(BUILD)/sample.inst.ll); \
	 echo "redirected mallocs: $$m"; test $$m -ge 1
	@if grep -qE 'call.*@malloc\(' $(BUILD)/sample.inst.ll; then \
	    echo "FAIL: malloc was not redirected"; exit 1; \
	 else echo "malloc redirected"; fi
	@for t in atomic atomic_rmw indirect extern_call inline_asm privileged \
	          tls setjmp vla; do \
	    $(CLANG) -O1 -S -emit-llvm $(SAMPLES)/$$t.c -o $(BUILD)/$$t.ll; \
	    if $(OPT) -load-pass-plugin=$(PLUGIN) -passes=encbound -S \
	        $(BUILD)/$$t.ll -o /dev/null 2>$(BUILD)/$$t.err; then \
	        echo "FAIL: $$t was not rejected"; exit 1; \
	    else echo "rejected as expected: $$t"; fi; \
	done
	@printf 'app_helper\n' > $(BUILD)/admitted.txt
	$(CLANG) -O1 -S -emit-llvm $(SAMPLES)/admitted.c -o $(BUILD)/admitted.ll
	$(OPT) -load-pass-plugin=$(PLUGIN) -passes=encbound \
	    -encbound-admitted-file=$(BUILD)/admitted.txt -S \
	    $(BUILD)/admitted.ll -o $(BUILD)/admitted.inst.ll
	@grep -q 'call i32 @app_helper' $(BUILD)/admitted.inst.ll \
	    && echo "admitted external call passed"
	@if $(OPT) -load-pass-plugin=$(PLUGIN) -passes=encbound -S \
	    $(BUILD)/admitted.ll -o /dev/null 2>/dev/null; then \
	    echo "FAIL: unlisted external was admitted"; exit 1; \
	else echo "unlisted external rejected"; fi
	$(CLANG) -O1 -fno-builtin -S -emit-llvm $(SAMPLES)/libcalls.c \
	    -o $(BUILD)/libcalls.ll
	$(OPT) -load-pass-plugin=$(PLUGIN) -passes=encbound -S \
	    $(BUILD)/libcalls.ll -o $(BUILD)/libcalls.inst.ll
	@grep -q '@encbound_memcpy' $(BUILD)/libcalls.inst.ll && \
	    grep -q '@encbound_strlen' $(BUILD)/libcalls.inst.ll && \
	    echo "library calls redirected to checked adapters"
	@printf 'seal_wallet\nsgx_seal_data = encbound_sgx_seal_data\n' > \
	    $(BUILD)/sdk_admitted.txt
	@printf 'sgx_unseal_data = encbound_sgx_unseal_data\n' >> \
	    $(BUILD)/sdk_admitted.txt
	@printf 'ocall_is_wallet = encbound_ocall_is_wallet\n' >> \
	    $(BUILD)/sdk_admitted.txt
	@printf 'ocall_save_wallet = encbound_ocall_save_wallet\n' >> \
	    $(BUILD)/sdk_admitted.txt
	@printf 'ocall_load_wallet = encbound_ocall_load_wallet\n' >> \
	    $(BUILD)/sdk_admitted.txt
	@printf 'ocall_debug_print = encbound_ocall_debug_print\n' >> \
	    $(BUILD)/sdk_admitted.txt
	$(CLANG) -O0 -Xclang -disable-O0-optnone -S -emit-llvm \
	    $(SAMPLES)/sdkservices.c -o $(BUILD)/sdkservices.ll
	$(OPT) -load-pass-plugin=$(PLUGIN) -passes=encbound \
	    -encbound-admitted-file=$(BUILD)/sdk_admitted.txt -S \
	    $(BUILD)/sdkservices.ll -o $(BUILD)/sdkservices.inst.ll
	@for s in encbound_sgx_seal_data encbound_sgx_unseal_data \
	          encbound_ocall_is_wallet encbound_ocall_save_wallet \
	          encbound_ocall_load_wallet encbound_ocall_debug_print; do \
	    grep -q "@$$s" $(BUILD)/sdkservices.inst.ll || \
	        { echo "FAIL: $$s not selected"; exit 1; }; \
	done
	@echo "SDK/OCALL calls redirected to checked adapters"
	@grep -q 'call i32 @seal_wallet' $(BUILD)/sdkservices.inst.ll && \
	    echo "cross-TU app function admitted, not redirected"
	@if grep -qE 'call .*@(sgx_seal_data|sgx_unseal_data|ocall_is_wallet|ocall_save_wallet|ocall_load_wallet|ocall_debug_print)\(' \
	    $(BUILD)/sdkservices.inst.ll; then \
	    echo "FAIL: raw SDK/bridge symbol still called"; exit 1; \
	 else echo "no raw SDK/bridge call sites remain"; fi
	ENCBOUND_PROFILE=MAC27 $(ROOT)/tools/encbound-cc.sh $(SAMPLES)/sample.c \
	    $(BUILD)/sample.o -O1
	@file $(BUILD)/sample.o | grep -q ELF && echo "driver emitted an ELF object"
	@python3 $(ROOT)/tools/encbound_inventory.py audit --object $(BUILD)/sample.o \
	    --expect instrumented --profile MAC27
	$(CLANG) -O1 -c $(SAMPLES)/sample.c -o $(BUILD)/sample.plain.o
	@if python3 $(ROOT)/tools/encbound_inventory.py audit \
	    --object $(BUILD)/sample.plain.o --expect instrumented --profile MAC27; then \
	    echo "FAIL: uninstrumented object was accepted"; exit 1; \
	else echo "uninstrumented object detected by the audit"; fi
	@python3 $(ROOT)/tools/encbound_inventory.py audit \
	    --object $(BUILD)/sample.plain.o --expect trusted \
	    && echo "trusted-domain check works"
	@if python3 $(ROOT)/tools/encbound_inventory.py audit \
	    --object $(BUILD)/sample.o --expect instrumented --profile RADIX_ONLY \
	    >/dev/null 2>&1; then \
	    echo "FAIL: wrong-profile marker was accepted"; exit 1; \
	else echo "wrong-profile marker rejected by the audit"; fi
	@if python3 $(ROOT)/tools/encbound_inventory.py audit \
	    --object $(BUILD)/sample.o --expect trusted >/dev/null 2>&1; then \
	    echo "FAIL: instrumented object accepted as trusted"; exit 1; \
	else echo "instrumented object rejected from trusted domain"; fi

clean:
	rm -rf $(BUILD)
