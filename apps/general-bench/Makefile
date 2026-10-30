# Bounded general-C benchmark experiment. Application kernels always pass
# through the same frontend/codegen pipeline; SDK/runtime remain trusted.
ROOT := $(abspath ../..)
HERE := $(CURDIR)
SGX_SDK ?= $(ROOT)/deps/sgxsdk
PINNED_SRC ?= $(ROOT)/deps/intel-sgx
PROFILE ?= MAC27
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
APP_FRONTEND_OPT ?= -O2
APP_CODEGEN_OPT ?= -O2
LOCAL_PROOFS ?= 0
FAST_PATHS ?= off
MAC_ALGORITHM ?= siphash24
ifeq ($(filter $(MAC_ALGORITHM),siphash24 aes128_cmac),)
$(error unsupported MAC_ALGORITHM)
endif
ifeq ($(filter $(LOCAL_PROOFS),0 1),)
$(error unsupported LOCAL_PROOFS)
endif
CHECK_REUSE ?= off
ifneq ($(filter $(CHECK_REUSE),off block loop),$(CHECK_REUSE))
$(error unsupported CHECK_REUSE)
endif
TRUSTED_OPT ?= -O2
TRUSTED_CORE ?= fused
ifeq ($(filter $(TRUSTED_OPT),-O0 -O2),)
$(error unsupported TRUSTED_OPT)
endif
ifneq ($(filter $(TRUSTED_CORE),separate fused),$(TRUSTED_CORE))
$(error unsupported TRUSTED_CORE)
endif
ifneq ($(SGX_MODE),SIM)
$(error this preliminary benchmark recipe supports SDK SIM only)
endif
ifneq ($(SGX_DEBUG),1)
$(error this preliminary recipe uses the validated debug runtime configuration)
endif
ifneq ($(APP_FRONTEND_OPT),-O2)
$(error this benchmark recipe fixes the frontend at -O2)
endif
ifneq ($(filter $(PROFILE),BASELINE RADIX_ONLY MAC27),$(PROFILE))
$(error unsupported PROFILE)
endif
ifeq ($(filter $(APP_CODEGEN_OPT),-O0 -O2),)
$(error unsupported APP_CODEGEN_OPT)
endif
include $(SGX_SDK)/buildenv.mk
BUILD ?= $(ROOT)/build/general-bench/SIM-$(PROFILE)-feO2-cg$(patsubst -%,%,$(APP_CODEGEN_OPT))-rt$(patsubst -%,%,$(TRUSTED_OPT))-$(TRUSTED_CORE)-reuse$(CHECK_REUSE)-proofs$(LOCAL_PROOFS)
ifneq ($(MAC_ALGORITHM),siphash24)
BUILD := $(BUILD)-mac$(MAC_ALGORITHM)
endif
E := $(BUILD)/enclave
H := $(BUILD)/host
G := $(BUILD)/generated
A := $(BUILD)/adapted
SDKLIB := $(SGX_SDK)/lib64
GENERATOR := $(ROOT)/build/edger8r/sgx_edger8r
PLUGIN := $(ROOT)/build/pass/encbound_pass.so
ifeq ($(MAC_ALGORITHM),aes128_cmac)
$(H)/host.o: CFLAGS_HOST_MAC := -DENCBOUND_HOST_REQUIRE_AES
endif
COMMON := -m64 -O0 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
INCLUDES := -I$(HERE) -I$(G) -I$(ROOT)/include -I$(ROOT)/runtime -I$(ROOT)/sdk \
 -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -isystem $(PINNED_SRC)/common/inc/internal
EFLAGS := $(COMMON) $(INCLUDES) -nostdinc -fvisibility=hidden -fpie \
 -ffunction-sections -fdata-sections -fstack-protector-strong $(MITIGATION_CFLAGS) -MMD -MP
DEFINES :=
APP := driver lists heapsort atax gemm jacobi
TRUSTED := enclave_t
ifneq ($(PROFILE),BASELINE)
DEFINES += -DENCBOUND_PROTECTED
TRUSTED += boundary_support platform_layout siphash runtime capability allocations allocator adapters
ifeq ($(TRUSTED_CORE),fused)
TRUSTED := $(filter-out siphash runtime capability,$(TRUSTED)) check_core
endif
endif
ifeq ($(PROFILE),MAC27)
DEFINES += -DENCBOUND_MAC27
ifeq ($(MAC_ALGORITHM),aes128_cmac)
$(E)/check_core.o $(E)/runtime.o: EFLAGS += -maes
DEFINES += -DENCBOUND_AES_CMAC
endif
endif
OBJS := $(addprefix $(E)/,$(addsuffix .o,$(APP) $(TRUSTED)))
GEN := $(addprefix $(G)/,enclave_t.c enclave_t.h enclave_u.c enclave_u.h enclave_app.c enclave_app.h admitted-app.txt admitted-ocalls.txt boundary-manifest.json)
UPSTREAM := $(shell find $(HERE)/upstream -type f)
ADAPTED := $(addprefix $(A)/,$(addsuffix .c,lists heapsort atax gemm jacobi))
LINK := $(MITIGATION_LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--no-undefined \
 -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
 -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
 -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
 -Wl,-Bstatic -Wl,-Bsymbolic -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
 -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
 -Wl,--version-script=$(ROOT)/sdk/enclave.lds -Wl,-T,$(ROOT)/sdk/enclave_sections.lds
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.PHONY: all audit pins FORCE
all: audit
$(E) $(H) $(G) $(A):
	mkdir -p $@
$(GENERATOR): $(wildcard $(ROOT)/tools/edger8r/*.ml $(ROOT)/tools/edger8r/*.mll $(ROOT)/tools/edger8r/*.mly) $(ROOT)/tools/edger8r/Makefile
	$(MAKE) -C $(ROOT)/tools/edger8r
$(PLUGIN): $(ROOT)/pass/encbound_pass.cpp $(ROOT)/pass/encbound_fast_paths.h $(ROOT)/pass/encbound_integration.h $(ROOT)/pass/Makefile $(ROOT)/pass/encbound_vla.h
	$(MAKE) -C $(ROOT)/pass
$(ADAPTED) &: prepare.py $(UPSTREAM) | $(A)
	python3 prepare.py $(A)
$(GEN) &: enclave.edl boundary-interface.json $(ROOT)/tools/modified_bridge.py $(GENERATOR) $(ROOT)/sdk/modified_bridge.h | $(G)
	python3 $(ROOT)/tools/modified_bridge.py --edl enclave.edl --interface boundary-interface.json \
	 --generator $(GENERATOR) --out-dir $(G) --profile $(PROFILE) --search-path $(SGX_SDK)/include \
	 --cc $(CC) --layout-cc clang-21 $(addprefix --cflag=,$(INCLUDES) -nostdinc)
define app_compile
	ENCBOUND_FAST_PATHS=$(FAST_PATHS) ENCBOUND_LOCAL_PROOFS=$(LOCAL_PROOFS) ENCBOUND_CHECK_REUSE=$(CHECK_REUSE) ENCBOUND_PROFILE=$(PROFILE) ENCBOUND_CODEGEN_OPT=$(APP_CODEGEN_OPT) ENCBOUND_ADMITTED=$(HERE)/admitted-symbols.txt \
	 $(ROOT)/tools/encbound-cc.sh $< $@ $(EFLAGS) -O2 -ffp-contract=off
	python3 prepare.py --mark $@
endef
$(E)/driver.o: driver.c bench.h $(GEN) $(PLUGIN) $(ROOT)/tools/encbound-cc.sh admitted-symbols.txt | $(E)
	$(app_compile)
$(E)/%.o: $(A)/%.c bench.h $(GEN) $(PLUGIN) $(ROOT)/tools/encbound-cc.sh admitted-symbols.txt | $(E)
	$(app_compile)
$(E)/enclave_t.o: $(G)/enclave_t.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/boundary_support.o: $(ROOT)/sdk/boundary_support.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/platform_layout.o: $(ROOT)/sdk/platform_layout.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/%.o: $(ROOT)/runtime/%.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/enclave.so: $(OBJS) $(ROOT)/sdk/enclave.lds $(ROOT)/sdk/enclave_sections.lds
	$(CC) $(OBJS) -o $@ $(LINK) -Wl,-Map,$(E)/enclave.map
$(BUILD)/test-key.pem: | $(E)
	openssl genrsa -out $@ -3 3072
$(BUILD)/sizing.xml: enclave.config.tmpl.xml $(ROOT)/tools/sgx_metadata.py | $(E)
	python3 $(ROOT)/tools/sgx_metadata.py render-config --template $< --base 0x40000000 --size 0x40000000 --out $@
$(BUILD)/sizing.so: $(E)/enclave.so $(BUILD)/sizing.xml $(BUILD)/test-key.pem
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config $(BUILD)/sizing.xml
$(BUILD)/extent: $(BUILD)/sizing.so
	python3 $(ROOT)/tools/sgx_metadata.py required --signed $< > $@
$(BUILD)/final.xml: enclave.config.tmpl.xml $(BUILD)/extent
	python3 $(ROOT)/tools/sgx_metadata.py render-config --template $< --base 0x40000000 --size "$$(cat $(BUILD)/extent)" --out $@
$(E)/enclave.signed.so: $(E)/enclave.so $(BUILD)/final.xml $(BUILD)/test-key.pem
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config $(BUILD)/final.xml
	python3 $(ROOT)/tools/sgx_metadata.py verify --signed $@ --base 0x40000000 --size "$$(cat $(BUILD)/extent)"
$(H)/host.o: host.c bench.h $(GEN) | $(H)
	$(CC) $(COMMON) $(CFLAGS_HOST_MAC) -DSGX_HOST -I$(HERE) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/enclave_u.o: $(G)/enclave_u.c $(GEN) | $(H)
	$(CC) $(COMMON) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/host: $(H)/host.o $(H)/enclave_u.o
	$(CC) $^ -o $@ -L$(SDKLIB) -Wl,-rpath-link,$(SDKLIB) -lsgx_urts_sim -lpthread
pins:
	python3 $(ROOT)/tools/check_sdk_pins.py --sdk $(SGX_SDK) --pinned $(PINNED_SRC)
	python3 -c 'import prepare; prepare.verify()'
audit: $(H)/host $(E)/enclave.signed.so pins
	python3 audit.py --build $(BUILD) --profile $(PROFILE) --codegen=$(APP_CODEGEN_OPT) --trusted-opt=$(TRUSTED_OPT) --trusted-core=$(TRUSTED_CORE) --check-reuse=$(CHECK_REUSE) --local-proofs=$(LOCAL_PROOFS) --fast-paths=$(FAST_PATHS) --mac-algorithm=$(MAC_ALGORITHM) --sdk $(SGX_SDK)
# Configuration changes must rebuild even when BUILD is explicitly reused.
FORCE:
$(BUILD)/build-config.json: FORCE | $(E)
	python3 -c 'import json,pathlib; p=pathlib.Path("$@"); s=json.dumps(dict(profile="$(PROFILE)",codegen="$(APP_CODEGEN_OPT)",trusted_opt="$(TRUSTED_OPT)",trusted_core="$(TRUSTED_CORE)",check_reuse="$(CHECK_REUSE)",local_proofs=int("$(LOCAL_PROOFS)"),fast_paths="$(FAST_PATHS)",mac_algorithm="$(MAC_ALGORITHM)"),sort_keys=True)+"\n"; p.write_text(s) if not p.exists() or p.read_text()!=s else None'
$(OBJS) $(H)/host.o $(H)/enclave_u.o: Makefile $(BUILD)/build-config.json
$(addprefix $(E)/,$(addsuffix .o,$(APP))): prepare.py $(ROOT)/tools/mark_appdata_sections.sh
-include $(wildcard $(E)/*.d $(H)/*.d) $(G)/boundary.d
