# Selected instrumented libc formatter service. Application units always pass
# through the same frontend/codegen pipeline; SDK/runtime remain trusted.
ROOT := $(abspath ../..)
HERE := $(CURDIR)
SGX_SDK ?= $(ROOT)/deps/sgxsdk
PINNED_SRC ?= $(ROOT)/deps/intel-sgx
PROFILE ?= MAC27
ENCLAVE_BASE ?= 0x40000000
APP_KIND := libc-format
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
APP_FRONTEND_OPT ?= -O2
APP_CODEGEN_OPT ?= -O2
LOCAL_PROOFS ?= 0
FAST_PATHS ?= off
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
BUILD ?= $(ROOT)/build/libc-format/SIM-$(PROFILE)-feO2-cg$(patsubst -%,%,$(APP_CODEGEN_OPT))-rt$(patsubst -%,%,$(TRUSTED_OPT))-$(TRUSTED_CORE)-reuse$(CHECK_REUSE)
ifeq ($(LOCAL_PROOFS),1)
BUILD := $(BUILD)-proofs1
endif
ifneq ($(FAST_PATHS),off)
BUILD := $(BUILD)-fast$(FAST_PATHS)
endif
E := $(BUILD)/enclave
H := $(BUILD)/host
G := $(BUILD)/generated
SDKLIB := $(SGX_SDK)/lib64
GENERATOR := $(ROOT)/build/edger8r/sgx_edger8r
PLUGIN := $(ROOT)/build/pass/encbound_pass.so
COMMON := -m64 -O0 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
INCLUDES := -I$(HERE) -I$(G) -I$(ROOT)/include -I$(ROOT)/runtime -I$(ROOT)/sdk \
 -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -isystem $(PINNED_SRC)/common/inc/internal
EFLAGS := $(COMMON) $(INCLUDES) -nostdinc -fvisibility=hidden -fpie \
 -ffunction-sections -fdata-sections -fstack-protector-strong $(MITIGATION_CFLAGS) -MMD -MP
DEFINES :=
ifeq ($(PROFILE),BASELINE)
DEFINES += -DENCBOUND_CXX_BASELINE
endif
LIBBUILD := $(ROOT)/build/libc-format/$(PROFILE)
LIBOBJS := $(shell python3 -c 'import json;print(" ".join(json.load(open("$(LIBBUILD)/build.json"))["objects"]))')
APP := service dispatch
ifneq ($(PROFILE),BASELINE)
APP += edl_app
endif
APP_INCLUDES := $(shell python3 -c 'import json;print(" ".join(f for f in json.load(open("$(LIBBUILD)/build.json"))["flags"] if f!="-std=c99"))') -std=c++17 -fno-exceptions -fno-rtti
TRUSTED := enclave_t cxx_services layout_checks
ifneq ($(PROFILE),BASELINE)
DEFINES += -DENCBOUND_PROTECTED
TRUSTED += boundary_support platform_layout siphash runtime capability allocations allocator adapters
ifeq ($(TRUSTED_CORE),fused)
TRUSTED := $(filter-out siphash runtime capability,$(TRUSTED)) check_core
endif
endif
ifeq ($(PROFILE),MAC27)
DEFINES += -DENCBOUND_MAC27
endif
OBJS := $(addprefix $(E)/,$(addsuffix .o,$(APP) $(TRUSTED)))
GEN := $(addprefix $(G)/,enclave_t.c enclave_t.h enclave_u.c enclave_u.h enclave_app.c enclave_app.h admitted-app.txt admitted-ocalls.txt boundary-manifest.json)

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
$(E) $(H) $(G):
	mkdir -p $@
$(GENERATOR): $(wildcard $(ROOT)/tools/edger8r/*.ml $(ROOT)/tools/edger8r/*.mll $(ROOT)/tools/edger8r/*.mly) $(ROOT)/tools/edger8r/Makefile
	$(MAKE) -C $(ROOT)/tools/edger8r BUILD=$(ROOT)/build/edger8r
$(PLUGIN): $(wildcard $(ROOT)/pass/*.h) $(ROOT)/pass/encbound_pass.cpp $(ROOT)/pass/Makefile
	$(MAKE) -C $(ROOT)/pass BUILD=$(ROOT)/build/pass PLUGIN=$(PLUGIN)
$(GEN) &: enclave.edl boundary-interface.json $(ROOT)/tools/modified_bridge.py $(GENERATOR) $(ROOT)/sdk/modified_bridge.h | $(G)
	python3 $(ROOT)/tools/modified_bridge.py --wide-scalars --edl enclave.edl --interface boundary-interface.json \
	 --generator $(GENERATOR) --out-dir $(G) --profile $(PROFILE) --search-path $(SGX_SDK)/include \
	 --cc $(CC) --layout-cc clang-21 $(addprefix --cflag=,$(INCLUDES) -nostdinc)
$(BUILD)/admitted.txt: $(LIBBUILD)/admitted.txt $(G)/admitted-ocalls.txt $(G)/admitted-app.txt
	cat $^ > $@
define app_compile
	ENCBOUND_APP_ERRNO=1 ENCBOUND_VARIADICS=1 ENCBOUND_ATOMICS=1 ENCBOUND_VIRTUALS=1 ENCBOUND_CALLBACKS=1 ENCBOUND_AGGREGATE_ABI=1 ENCBOUND_CXX_ALLOCATIONS=1 ENCBOUND_FAST_PATHS=$(FAST_PATHS) ENCBOUND_LOCAL_PROOFS=$(LOCAL_PROOFS) ENCBOUND_CHECK_REUSE=$(CHECK_REUSE) ENCBOUND_PROFILE=$(PROFILE) ENCBOUND_CODEGEN_OPT=$(APP_CODEGEN_OPT) ENCBOUND_ADMITTED=$(BUILD)/admitted.txt \
	 $(COMPILER) $< $@ $(EFLAGS) -fno-common -fno-builtin $(APP_INCLUDES) -include $(G)/enclave_t.h -O2
	ENCBOUND_WRITABLE_GLOBALS=1 $(ROOT)/tools/mark_appdata_sections.sh $@ $@.placed
	mv $@.placed $@
	mv $@.placed.ownership.json $@.ownership.json
endef
$(E)/service.o $(E)/dispatch.o: COMPILER=$(ROOT)/tools/encbound-cc.sh
$(E)/service.o: service.cpp api.h $(BUILD)/admitted.txt $(GEN) $(PLUGIN) $(LIBBUILD)/admitted.txt $(LIBBUILD)/build.json | $(E)
	$(app_compile)
$(E)/dispatch.o: dispatch.cpp api.h $(BUILD)/admitted.txt $(GEN) $(PLUGIN) $(LIBBUILD)/admitted.txt $(LIBBUILD)/build.json | $(E)
	$(app_compile)
$(E)/edl_app.o: COMPILER=$(ROOT)/tools/encbound-cc.sh
$(E)/edl_app.o: APP_INCLUDES += -x c++
$(E)/edl_app.o: $(G)/enclave_app.c $(BUILD)/admitted.txt $(GEN) $(PLUGIN) $(LIBBUILD)/build.json | $(E)
	$(app_compile)
$(E)/layout_checks.o: layout_checks.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/enclave_t.o: $(G)/enclave_t.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/boundary_support.o: $(ROOT)/sdk/boundary_support.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/platform_layout.o: $(ROOT)/sdk/platform_layout.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/%.o: $(ROOT)/runtime/%.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/enclave.so: $(LIBBUILD)/libencbound_format.a $(OBJS) $(ROOT)/sdk/enclave.lds $(ROOT)/sdk/enclave_sections.lds
	$(CC) $(OBJS) $(LIBOBJS) -o $@ $(LINK) -Wl,-Map,$(E)/enclave.map
$(BUILD)/test-key.pem: | $(E)
	openssl genrsa -out $@ -3 3072
$(BUILD)/sizing.xml: enclave.config.tmpl.xml $(ROOT)/tools/sgx_metadata.py | $(E)
	python3 $(ROOT)/tools/sgx_metadata.py render-config --template $< --base $(ENCLAVE_BASE) --size 0x40000000 --out $@
$(BUILD)/sizing.so: $(E)/enclave.so $(BUILD)/sizing.xml $(BUILD)/test-key.pem
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config $(BUILD)/sizing.xml
$(BUILD)/extent: $(BUILD)/sizing.so
	python3 $(ROOT)/tools/sgx_metadata.py required --signed $< > $@
$(BUILD)/final.xml: enclave.config.tmpl.xml $(BUILD)/extent
	python3 $(ROOT)/tools/sgx_metadata.py render-config --template $< --base $(ENCLAVE_BASE) --size "$$(cat $(BUILD)/extent)" --out $@
$(E)/enclave.signed.so: $(E)/enclave.so $(BUILD)/final.xml $(BUILD)/test-key.pem
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config $(BUILD)/final.xml
	python3 $(ROOT)/tools/sgx_metadata.py verify --signed $@ --base $(ENCLAVE_BASE) --size "$$(cat $(BUILD)/extent)"
$(H)/host.o: host.c $(GEN) | $(H)
	$(CC) $(COMMON) -DSGX_HOST -I$(HERE) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/enclave_u.o: $(G)/enclave_u.c $(GEN) | $(H)
	$(CC) $(COMMON) -I$(HERE) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/host: $(H)/host.o $(H)/enclave_u.o
	$(CC) $^ -o $@ -L$(SDKLIB) -Wl,-rpath-link,$(SDKLIB) -lsgx_urts_sim -lpthread
pins:
	python3 $(ROOT)/tools/check_sdk_pins.py --sdk $(SGX_SDK) --pinned $(PINNED_SRC)
	python3 $(ROOT)/apps/libc-format/verify.py --library-build $(LIBBUILD)
audit: $(H)/host $(E)/enclave.signed.so pins
	python3 audit.py --build $(BUILD) --profile $(PROFILE) --library-build $(LIBBUILD)

# Configuration changes must rebuild even when BUILD is explicitly reused.
FORCE:
$(BUILD)/build-config.json: FORCE | $(E)
	python3 -c 'import json,pathlib; p=pathlib.Path("$@"); s=json.dumps(dict(app="$(APP_KIND)",base="$(ENCLAVE_BASE)",profile="$(PROFILE)",codegen="$(APP_CODEGEN_OPT)",trusted_opt="$(TRUSTED_OPT)",trusted_core="$(TRUSTED_CORE)",check_reuse="$(CHECK_REUSE)",local_proofs=int("$(LOCAL_PROOFS)"),fast_paths="$(FAST_PATHS)"),sort_keys=True)+"\n"; p.write_text(s) if not p.exists() or p.read_text()!=s else None'
$(OBJS) $(H)/host.o $(H)/enclave_u.o: Makefile $(BUILD)/build-config.json
$(addprefix $(E)/,$(addsuffix .o,$(APP))): $(ROOT)/apps/libc-format/verify.py $(ROOT)/tools/mark_appdata_sections.sh $(ROOT)/tools/mark_app_globals.py $(ROOT)/tools/encbound-cxx.sh $(ROOT)/tools/prepare_cxx_headers.py $(ROOT)/tools/record_integration_unit.py
-include $(wildcard $(E)/*.d $(H)/*.d) $(G)/boundary.d
