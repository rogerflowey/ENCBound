#
# ENCBound restart - sgx-wallet candidate build (step 0).
#
# Reads the pinned upstream source tree read-only. The upstream enclave is
# .cpp but semantically C; it is compiled here as C via -x c so the candidate
# does not pull in the trusted C++ runtime. Generated files and artifacts go
# under ../../build/apps/sgx-wallet.
#
# Run as: make -C apps/sgx-wallet [benign|overflow|boundary] [ARGS="--wallet-size 16 --capacity 30112"]
#

SGX_SDK ?= $(abspath ../../deps/sgxsdk)
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
PROFILE ?= BASELINE
APP_SRC ?= $(abspath ../../build/paper-sources/sgx-wallet)
ENCLAVE_BASE ?= 0x40000000

# Frontend optimization for the application translation units only
# (docs/legacy/steps/04a-capability-semantics.md C0/C4). This controls the pre-transform
# `clang -S -emit-llvm` level. Omitted from the build path for the default
# `-O0` so existing debug evidence directories are unchanged; a non-default level
# gets its own `-fe<level>` directory so the two rows cannot clobber each other.
APP_FRONTEND_OPT ?= -O0
# Experimental machine-code optimization; no later general IR pipeline or LTO.
APP_CODEGEN_OPT ?= -O0
ifeq ($(filter $(APP_CODEGEN_OPT),-O0 -O2),)
$(error Unsupported APP_CODEGEN_OPT '$(APP_CODEGEN_OPT)': expected -O0 or -O2)
endif
ifeq ($(APP_CODEGEN_OPT),-O2)
ifneq ($(APP_FRONTEND_OPT),-O2)
$(error APP_CODEGEN_OPT=-O2 requires APP_FRONTEND_OPT=-O2 to avoid frontend optnone)
endif
endif
export ENCBOUND_CODEGEN_OPT := $(APP_CODEGEN_OPT)

# Pinned SDK source tree providing the internal layout headers used by
# sdk/platform_layout.c (the trusted platform binding). Matches sdk/Makefile.
PINNED_SRC ?= $(abspath ../../deps/intel-sgx)
PINNED_INCLUDE := $(PINNED_SRC)/common/inc/internal

# Reject unknown configuration spellings (static review P1, 2026-09-30).
ifeq ($(filter $(SGX_MODE),SIM HW),)
$(error Unknown SGX_MODE '$(SGX_MODE)': expected SIM or HW)
endif
ifeq ($(filter $(SGX_DEBUG),0 1),)
$(error Unknown SGX_DEBUG '$(SGX_DEBUG)': expected 0 or 1)
endif
ifeq ($(filter $(PROFILE),BASELINE RADIX_ONLY MAC27),)
$(error Unknown PROFILE '$(PROFILE)': expected BASELINE, RADIX_ONLY, or MAC27)
endif
ifneq ($(ENCLAVE_BASE),0x40000000)
$(error Unknown ENCLAVE_BASE '$(ENCLAVE_BASE)': expected 0x40000000)
endif

SRC_DIR := $(CURDIR)
ROOT := $(abspath $(SRC_DIR)/../..)

include $(SGX_SDK)/buildenv.mk

# The historical SIM-dbg1 baseline remains an old artifact; new experimental
# modified-bridge rows use a separate root to preserve prior evidence.
BUILD := $(ROOT)/build/apps/sgx-wallet-modified/$(SGX_MODE)-$(PROFILE)-dbg$(SGX_DEBUG)
ifneq ($(APP_FRONTEND_OPT),-O0)
BUILD := $(BUILD)-fe$(patsubst -%,%,$(APP_FRONTEND_OPT))
endif
ifneq ($(APP_CODEGEN_OPT),-O0)
BUILD := $(BUILD)-cg$(patsubst -%,%,$(APP_CODEGEN_OPT))
endif
HOST_BUILD := $(BUILD)/host
ENCLAVE_BUILD := $(BUILD)/enclave

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_EDGER8R := $(ROOT)/build/edger8r/sgx_edger8r
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
ENCBOUND_CC := $(ROOT)/tools/encbound-cc.sh
ENCBOUND_PLUGIN := $(ROOT)/build/pass/encbound_pass.so
# Pinned Clang used for the record layout AST probe. The trusted generated
# objects are compiled with $(CC); layout facts are established from the pinned
# LLVM 21 toolchain (see tools/check_wallet_pins.py).
LAYOUT_CC ?= clang-21
# Host C++ compiler for the pinned upstream host row (ordinary untrusted code).
CXX ?= g++

SGX_COMMON_FLAGS := -m64
ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_FLAGS += -O0 -g
else
    SGX_COMMON_FLAGS += -O2
endif
SGX_COMMON_FLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare

ifneq ($(SGX_MODE), HW)
    Urts_Library_Name := sgx_urts_sim
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
else
    Urts_Library_Name := sgx_urts
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
endif

Host_C_Flags := -fPIC -Wno-attributes -I$(HOST_BUILD) -I$(SGX_SDK)/include \
                -I$(APP_SRC)/include
Host_Link_Flags := -L$(SGX_LIBRARY_PATH) \
                   -Wl,-rpath-link,$(SGX_LIBRARY_PATH) \
                   -l$(Urts_Library_Name) -lpthread

Enclave_C_Flags := -I$(ENCLAVE_BUILD) -I$(APP_SRC)/include \
                   -I$(APP_SRC)/enclave -I$(ROOT)/wrappers -I$(ROOT)/sdk \
                   -I$(ROOT)/include -I$(ROOT)/runtime \
                   -I$(SGX_SDK)/include \
                   -I$(SGX_SDK)/include/tlibc -isystem $(PINNED_INCLUDE) \
                   -nostdinc -fvisibility=hidden \
                   -fpie -ffunction-sections -fdata-sections \
                   -fstack-protector-strong $(MITIGATION_CFLAGS)

# RADIX_ONLY is the absence of the MAC define (bounds/region checks only).
ifeq ($(PROFILE),MAC27)
    Enclave_C_Flags += -DENCBOUND_MAC27
endif

Enclave_Link_Flags := $(MITIGATION_LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    -L$(SGX_TRUSTED_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -l$(Service_Library_Name) \
    -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=$(ROOT)/sdk/enclave.lds

GEN_UNTRUSTED := $(HOST_BUILD)/enclave_u.c $(HOST_BUILD)/enclave_u.h
GEN_TRUSTED := $(ENCLAVE_BUILD)/enclave_t.c $(ENCLAVE_BUILD)/enclave_t.h
ENCLAVE_KEY := $(BUILD)/app_private_test.pem
HOST_BIN := $(HOST_BUILD)/host
SIGNED := $(ENCLAVE_BUILD)/enclave.signed.so

# All profiles use the same source, EDL, host lifecycle, compiler pipeline,
# signing resources and corresponding input/output copies.
PYTHON ?= python3
META := $(ROOT)/tools/sgx_metadata.py
MAX_ELRANGE := 0x40000000
SIZING_BUILD := $(BUILD)/sizing
SIZING_CONFIG := $(BUILD)/enclave.config.sizing.xml
SIZING_SIGNED := $(SIZING_BUILD)/enclave.signed.so
DERIVED_EXTENT := $(BUILD)/enclave.extent
FINAL_CONFIG := $(BUILD)/enclave.config.final.xml

EDL_SRC := $(SRC_DIR)/enclave.edl
POLICY := $(SRC_DIR)/boundary-interface.json
EDL_GEN := $(ROOT)/tools/modified_bridge.py
HOST_SRC := $(SRC_DIR)/session_host.c
SIGN_CONFIG := $(FINAL_CONFIG)

# Generated bridges and admission metadata; no companion runtime adapters.
GEN_DIR := $(BUILD)/encbound-generated
GEN_ADMITTED := $(GEN_DIR)/admitted-ocalls.txt
GEN_MANIFEST := $(GEN_DIR)/boundary-manifest.json
GEN_OUT := $(GEN_DIR)/enclave_t.c $(GEN_DIR)/enclave_t.h \
           $(GEN_DIR)/enclave_u.c $(GEN_DIR)/enclave_u.h \
           $(GEN_DIR)/enclave_app.c $(GEN_DIR)/enclave_app.h $(GEN_DIR)/admitted-app.txt \
           $(GEN_ADMITTED) $(GEN_MANIFEST)
MERGED_ADMITTED := $(BUILD)/admitted-symbols.merged.txt
BRIDGE_HEADER := $(ENCLAVE_BUILD)/enclave_t.h

# Generated bridge headers and shared trusted support.
Enclave_C_Flags += -I$(GEN_DIR)

# Include/type context for the generation-time ABI check against the pinned
# Intel-generated bridge header. Same headers the enclave objects compile with,
# including the pinned application types (wallet.h) and the shared support and
# runtime headers named by the emitted C.
GEN_CHECK_FLAGS := -I$(ENCLAVE_BUILD) -I$(GEN_DIR) -I$(ROOT)/include \
    -I$(ROOT)/sdk -I$(APP_SRC)/include \
    -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -nostdinc

APP_OBJECTS := $(ENCLAVE_BUILD)/enclave.o $(ENCLAVE_BUILD)/sealing.o
APP_TU_DEPS := $(ENCBOUND_CC) $(SRC_DIR)/admitted-symbols.txt \
    $(GEN_OUT)
ENCBOUND_ADMITTED_FILE := $(SRC_DIR)/admitted-symbols.txt
# Intel bridges call the original application symbols directly.
TRUSTED_OBJECTS := $(ENCLAVE_BUILD)/enclave_t.o
ifneq ($(PROFILE),BASELINE)
Enclave_C_Flags += -DENCBOUND_PROTECTED
APP_TU_DEPS += $(ENCBOUND_PLUGIN) $(MERGED_ADMITTED)
ENCBOUND_ADMITTED_FILE := $(MERGED_ADMITTED)
TRUSTED_OBJECTS += $(ENCLAVE_BUILD)/boundary_support.o \
    $(ENCLAVE_BUILD)/sdk_adapters.o \
    $(ENCLAVE_BUILD)/siphash.o $(ENCLAVE_BUILD)/runtime.o \
    $(ENCLAVE_BUILD)/capability.o $(ENCLAVE_BUILD)/allocations.o \
    $(ENCLAVE_BUILD)/allocator.o $(ENCLAVE_BUILD)/adapters.o \
    $(ENCLAVE_BUILD)/platform_layout.o
endif
ENCLAVE_OBJECTS := $(APP_OBJECTS) $(TRUSTED_OBJECTS)
define compile_app_tu
	ENCBOUND_PROFILE=$(PROFILE) \
	ENCBOUND_ADMITTED=$(ENCBOUND_ADMITTED_FILE) \
	    $(ENCBOUND_CC) $< $@ -x c $(SGX_COMMON_FLAGS) $(Enclave_C_Flags) $(APP_FRONTEND_OPT)
endef

ARGS ?=

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.PHONY: all benign overflow overflow-attribute optimized-copy boundary upstream protected audit pins clean

all: audit
	@echo "BUILD => sgx-wallet candidate (mode=$(SGX_MODE) debug=$(SGX_DEBUG))"
	@echo "BUILD => $(BUILD)"

$(SGX_EDGER8R): $(wildcard $(ROOT)/tools/edger8r/*.ml $(ROOT)/tools/edger8r/*.mll $(ROOT)/tools/edger8r/*.mly) $(ROOT)/tools/edger8r/Makefile
	$(MAKE) -C $(ROOT)/tools/edger8r

$(GEN_OUT) &: $(EDL_SRC) $(POLICY) $(EDL_GEN) $(SGX_EDGER8R) $(ROOT)/sdk/modified_bridge.h | $(BUILD)
	$(PYTHON) $(EDL_GEN) --edl $(EDL_SRC) --interface $(POLICY) \
	    --generator $(SGX_EDGER8R) --out-dir $(GEN_DIR) --profile $(PROFILE) \
	    --search-path $(APP_SRC)/include --search-path $(APP_SRC)/enclave \
	    --search-path $(ROOT)/sdk --search-path $(ROOT)/include \
	    --search-path $(SGX_SDK)/include --cc $(CC) --layout-cc $(LAYOUT_CC) \
	    $(addprefix --cflag=,$(GEN_CHECK_FLAGS))

$(GEN_UNTRUSTED) &: $(GEN_OUT) | $(HOST_BUILD)
	cp $(GEN_DIR)/enclave_u.c $(GEN_DIR)/enclave_u.h $(HOST_BUILD)/
$(GEN_TRUSTED) &: $(GEN_OUT) | $(ENCLAVE_BUILD)
	cp $(GEN_DIR)/enclave_t.c $(GEN_DIR)/enclave_t.h $(ENCLAVE_BUILD)/

# Merge directly admitted modified OCALL proxies with explicit library adapters.
$(MERGED_ADMITTED): $(SRC_DIR)/admitted-symbols.txt $(GEN_ADMITTED)
	cat $^ > $@
	@echo "GEN  => merged admitted symbols ($@)"

# Shared reusable boundary support (trusted, uninstrumented). Ordinary malloc in
# BASELINE; checked runtime allocation/capabilities in protected profiles.
$(ENCLAVE_BUILD)/boundary_support.o: $(ROOT)/sdk/boundary_support.c \
		$(ROOT)/sdk/boundary_support.h $(GEN_TRUSTED) | $(ENCLAVE_BUILD)
	$(CC) $(SGX_COMMON_FLAGS) $(Enclave_C_Flags) -c $< -o $@

$(BUILD) $(HOST_BUILD) $(ENCLAVE_BUILD):
	mkdir -p $@

$(HOST_BUILD)/enclave_u.o: $(HOST_BUILD)/enclave_u.c $(GEN_UNTRUSTED)
	$(CC) $(SGX_COMMON_FLAGS) $(Host_C_Flags) -c $< -o $@

$(HOST_BUILD)/host.o: $(HOST_SRC) $(GEN_UNTRUSTED)
	$(CC) $(SGX_COMMON_FLAGS) $(Host_C_Flags) -c $< -o $@

$(HOST_BIN): $(HOST_BUILD)/host.o $(HOST_BUILD)/enclave_u.o
	$(CC) $^ -o $@ $(Host_Link_Flags)
	@echo "LINK => $@"

# Pinned upstream host/test row (docs/legacy/steps/09). app/app.cpp, app/test.cpp and
# app/utils.cpp are compiled byte-for-byte unchanged (host C++, ordinary
# untrusted code) with their ECALL call sites intact. A missing upstream header
# (ocalls.h) is supplied by an ENCBound shim on the include path; no pinned
# source is edited. It links the same Intel untrusted bridge as the session host.
UPSTREAM_SHIM := $(SRC_DIR)/upstream-shim
UPSTREAM_HOST_SRC := $(APP_SRC)/app/app.cpp $(APP_SRC)/app/utils.cpp \
                     $(APP_SRC)/app/test.cpp
UPSTREAM_HOST_FLAGS := -fPIC -Wno-attributes -std=c++11 -MMD -MP \
                       -I$(HOST_BUILD) -I$(SGX_SDK)/include \
                       -I$(APP_SRC)/app -I$(APP_SRC)/include \
                       -I$(UPSTREAM_SHIM)
UPSTREAM_HOST_BIN := $(HOST_BUILD)/host-upstream
UPSTREAM_HOST_OBJECTS := $(HOST_BUILD)/upstream_app.o \
                         $(HOST_BUILD)/upstream_utils.o \
                         $(HOST_BUILD)/upstream_test.o \
                         $(HOST_BUILD)/enclave_u.o

$(HOST_BUILD)/upstream_app.o: $(APP_SRC)/app/app.cpp $(GEN_UNTRUSTED) \
		$(UPSTREAM_SHIM)/ocalls.h $(SRC_DIR)/Makefile | $(HOST_BUILD)
	$(CXX) $(SGX_COMMON_FLAGS) $(UPSTREAM_HOST_FLAGS) -c $< -o $@

$(HOST_BUILD)/upstream_utils.o: $(APP_SRC)/app/utils.cpp $(GEN_UNTRUSTED) \
		$(SRC_DIR)/Makefile | $(HOST_BUILD)
	$(CXX) $(SGX_COMMON_FLAGS) $(UPSTREAM_HOST_FLAGS) -c $< -o $@

$(HOST_BUILD)/upstream_test.o: $(APP_SRC)/app/test.cpp $(GEN_UNTRUSTED) \
		$(SRC_DIR)/Makefile | $(HOST_BUILD)
	$(CXX) $(SGX_COMMON_FLAGS) $(UPSTREAM_HOST_FLAGS) -c $< -o $@

$(UPSTREAM_HOST_BIN): $(UPSTREAM_HOST_OBJECTS)
	$(CXX) $^ -o $@ $(Host_Link_Flags)
	@echo "LINK => $@"

$(ENCLAVE_BUILD)/enclave_t.o: $(ENCLAVE_BUILD)/enclave_t.c $(GEN_TRUSTED)
	$(CC) $(SGX_COMMON_FLAGS) $(Enclave_C_Flags) -c $< -o $@

$(ENCLAVE_BUILD)/enclave.o: $(APP_SRC)/enclave/enclave.cpp $(GEN_TRUSTED) \
		$(APP_TU_DEPS)
	$(compile_app_tu)

$(ENCLAVE_BUILD)/sealing.o: $(APP_SRC)/enclave/sealing/sealing.cpp $(GEN_TRUSTED) \
		$(APP_TU_DEPS)
	$(compile_app_tu)

# Step 5 trusted boundary adapters. ENCBOUND_APP_ENCLAVE makes the bridge
# header include the authoritative generated enclave_t.h.
$(ENCLAVE_BUILD)/sdk_adapters.o: $(ROOT)/wrappers/sdk_adapters.c \
		$(ROOT)/wrappers/encbound_adapters.h \
		$(ROOT)/wrappers/sgx_wallet_bridge.h $(GEN_TRUSTED)
	$(CC) -DENCBOUND_APP_ENCLAVE $(SGX_COMMON_FLAGS) $(Enclave_C_Flags) -c $< -o $@

# Trusted checked runtime and the SDK platform binding, linked only in the
# protected profiles. These never pass through the instrumentation pass.
$(ENCLAVE_BUILD)/%.o: $(ROOT)/runtime/%.c $(GEN_TRUSTED)
	$(CC) $(SGX_COMMON_FLAGS) $(Enclave_C_Flags) -c $< -o $@

$(ENCLAVE_BUILD)/platform_layout.o: $(ROOT)/sdk/platform_layout.c \
		$(ROOT)/include/encbound_platform.h $(ROOT)/include/encbound_regions.h \
		$(GEN_TRUSTED)
	$(CC) $(SGX_COMMON_FLAGS) $(Enclave_C_Flags) -c $< -o $@

$(ENCLAVE_BUILD)/enclave.so: $(ENCLAVE_OBJECTS)
	$(CC) $(ENCLAVE_OBJECTS) -o $@ $(Enclave_Link_Flags) -Wl,-Map,$(ENCLAVE_BUILD)/enclave.map
	@echo "LINK => $@"

$(ENCLAVE_KEY): | $(BUILD)
	openssl genrsa -out $@ -3 3072

# Derived-extent signing, same construction as sdk/Makefile: sign once at the
# 1 GiB ceiling to learn the required extent from the signed metadata, then
# re-sign at the next power of two and verify the signed layout.
$(SIZING_CONFIG): $(SRC_DIR)/enclave.config.tmpl.xml $(META) | $(BUILD)
	$(PYTHON) $(META) render-config --template $< --base $(ENCLAVE_BASE) \
	    --size $(MAX_ELRANGE) --out $@

$(SIZING_SIGNED): $(ENCLAVE_BUILD)/enclave.so $(SIZING_CONFIG) $(ENCLAVE_KEY)
	@mkdir -p $(SIZING_BUILD)
	$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_KEY) \
	    -enclave $(ENCLAVE_BUILD)/enclave.so -out $@ -config $(SIZING_CONFIG)

$(DERIVED_EXTENT): $(SIZING_SIGNED) $(META)
	$(PYTHON) $(META) required --signed $< > $@
	@echo "EXTENT => $$(cat $@) (derived from signed metadata)"

$(FINAL_CONFIG): $(SRC_DIR)/enclave.config.tmpl.xml $(DERIVED_EXTENT) $(META)
	$(PYTHON) $(META) render-config --template $< --base $(ENCLAVE_BASE) \
	    --size "$$(cat $(DERIVED_EXTENT))" --out $@

$(SIGNED): $(ENCLAVE_BUILD)/enclave.so $(FINAL_CONFIG) $(ENCLAVE_KEY)
	$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_KEY) \
	    -enclave $(ENCLAVE_BUILD)/enclave.so -out $@ -config $(FINAL_CONFIG)
	$(PYTHON) $(META) verify --signed $@ --base $(ENCLAVE_BASE) \
	    --size "$$(cat $(DERIVED_EXTENT))"
	@echo "SIGN => $@"

benign: all
	cd $(ENCLAVE_BUILD) && LD_LIBRARY_PATH=$(SGX_LIBRARY_PATH):$$LD_LIBRARY_PATH $(HOST_BIN) $(ARGS)

overflow: all
	cd $(ENCLAVE_BUILD) && LD_LIBRARY_PATH=$(SGX_LIBRARY_PATH):$$LD_LIBRARY_PATH $(HOST_BIN) --overflow $(ARGS)

# Durable original-access attribution. Both an allocation-matching capacity and
# a larger host capacity must terminate at the original 30112-byte assignment's
# compiler-inserted RANGE check (tools/run_overflow_attribution.sh). Protected
# profiles only: BASELINE has no checked runtime.
ifneq ($(PROFILE),BASELINE)
overflow-attribute: all
	$(ROOT)/tools/run_overflow_attribution.sh $(BUILD) 16 16
	$(ROOT)/tools/run_overflow_attribution.sh $(BUILD) 30112 16
endif

# C4 optimized-frontend attribution: identify the original copy's emitted
# instruction and the enforcing checks directly from the object, with no
# source/debug frame. This is the row that holds when a frontend
# (APP_FRONTEND_OPT=-O2) inlines or coalesces the assignment; the -O0 debug row
# is covered by overflow-attribute. Protected profiles only.
optimized-copy:
	python3 $(ROOT)/tools/check_optimized_show_copy.py --selftest
ifneq ($(PROFILE),BASELINE)
optimized-copy: all
	python3 $(ROOT)/tools/check_optimized_show_copy.py --build $(BUILD) --width 30112
endif

# Exercise the generated ECALL lifecycle's boundary rules in the enclave
# (SDK-compatible geometry, application errors, host failures and nested entry).
boundary: all
	cd $(ENCLAVE_BUILD) && LD_LIBRARY_PATH=$(SGX_LIBRARY_PATH):$$LD_LIBRARY_PATH $(HOST_BIN) --boundary

# Pinned upstream host/test row: run app/app.cpp (compiled unchanged) so its
# original ECALL call sites exercise create/add/change/remove/show on one
# enclave (app/test.cpp) and across processes (CLI, sealed wallet persists).
upstream: all $(UPSTREAM_HOST_BIN)
	$(ROOT)/tools/run_upstream_host.sh $(BUILD) $(SGX_SDK)

protected: all
	@echo "BUILD => instrumented sgx-wallet enclave (mode=$(SGX_MODE) profile=$(PROFILE) debug=$(SGX_DEBUG))"
	@echo "BUILD => $(BUILD)"

# Fail before execution if any pin, object domain, external call or retained
# adapter differs from the closed inventory. Trusted objects are audited too.
audit: $(HOST_BIN) $(SIGNED) pins
	ENCBOUND_RECORD_FLAGS='$(SGX_COMMON_FLAGS) $(Enclave_C_Flags) $(APP_FRONTEND_OPT)' \
	ENCBOUND_RECORD_CODEGEN_FLAGS='$(APP_CODEGEN_OPT) -Xclang -disable-llvm-passes' \
	ENCBOUND_RECORD_HOST_FLAGS='$(Host_C_Flags)' \
	$(PYTHON) $(ROOT)/tools/record_build_identity.py --build $(BUILD) \
	    --profile $(PROFILE) --mode $(SGX_MODE) --debug $(SGX_DEBUG) \
	    --cc '$(CC)' --cxx '$(CXX)' --layout-cc '$(LAYOUT_CC)' \
	    --driver '$(ENCBOUND_CC)' --plugin '$(ENCBOUND_PLUGIN)' \
	    --generator '$(EDL_GEN)' --edger8r '$(SGX_EDGER8R)' \
	    --signer '$(SGX_ENCLAVE_SIGNER)'
	$(PYTHON) $(ROOT)/tools/audit_wallet.py --build $(BUILD) --profile $(PROFILE)

pins:
	$(PYTHON) $(ROOT)/tools/check_sdk_pins.py --sdk $(SGX_SDK) --pinned $(PINNED_SRC)
	$(PYTHON) $(ROOT)/tools/check_wallet_pins.py --source $(APP_SRC)

$(ENCBOUND_PLUGIN): $(ROOT)/pass/encbound_pass.cpp $(ROOT)/pass/encbound_fast_paths.h $(ROOT)/pass/encbound_integration.h $(ROOT)/pass/Makefile $(ROOT)/pass/encbound_vla.h
	$(MAKE) -C $(ROOT)/pass all

# Make/header changes cannot silently leave old objects behind. The driver emits
# dependencies for application headers; trusted compilations do the same.
Enclave_C_Flags += -MMD -MP
Host_C_Flags += -MMD -MP
$(ENCLAVE_OBJECTS) $(HOST_BUILD)/host.o $(HOST_BUILD)/enclave_u.o: $(SRC_DIR)/Makefile
$(GEN_UNTRUSTED) $(GEN_TRUSTED): | pins
$(ENCLAVE_BUILD)/enclave.so: $(ROOT)/sdk/enclave.lds
-include $(wildcard $(ENCLAVE_BUILD)/*.d $(HOST_BUILD)/*.d)
-include $(wildcard $(GEN_DIR)/boundary.d)

clean:
	rm -rf $(BUILD)
