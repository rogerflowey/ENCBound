# Bounded ConFlow forward/backward operators. Recipe origin: apps/fedserving.
# The upstream checkout is prepared under BUILD; no upstream file is modified.
ROOT := $(abspath ../..)
HERE := $(CURDIR)
SGX_SDK ?= $(ROOT)/deps/sgxsdk
PINNED_SRC ?= $(ROOT)/deps/intel-sgx
SOURCE ?= $(ROOT)/build/conflow/source
PROFILE ?= MAC27
ENCLAVE_BASE ?= 0x40000000
SGX_MODE ?= SIM
SGX_DEBUG ?= 1
APP_FRONTEND_OPT ?= -O2
APP_CODEGEN_OPT ?= -O2
TRUSTED_OPT ?= -O2
TRUSTED_CORE ?= fused
include $(SGX_SDK)/buildenv.mk
ifeq ($(filter $(PROFILE),BASELINE RADIX_ONLY MAC27),)
$(error unsupported PROFILE)
endif
ifneq ($(SGX_MODE),SIM)
$(error this preliminary recipe supports SDK SIM only)
endif
ifneq ($(SGX_DEBUG),1)
$(error this preliminary recipe uses the validated debug runtime configuration)
endif
ifneq ($(APP_FRONTEND_OPT),-O2)
$(error this recipe fixes the frontend at -O2)
endif
ifneq ($(APP_CODEGEN_OPT),-O2)
$(error this recipe fixes code generation at -O2)
endif
ifeq ($(filter $(TRUSTED_OPT),-O0 -O2),)
$(error unsupported TRUSTED_OPT)
endif
ifeq ($(filter $(TRUSTED_CORE),separate fused),)
$(error unsupported TRUSTED_CORE)
endif

# New-integration defaults.  Explicit ENCBOUND_* environment settings still
# describe the closure and are checked below.
include $(ROOT)/config/integration.env
ifeq ($(ENCBOUND_INTEGRATION_PRESET),all-compat-v1)
else
$(error the all-compat integration preset is required)
endif
export ENCBOUND_PROFILE := $(PROFILE)
export ENCBOUND_ADMITTED = $(BUILD)/admitted.txt

BUILD ?= $(ROOT)/build/conflow/SIM-$(PROFILE)-feO2-cg$(patsubst -%,%,$(APP_CODEGEN_OPT))-rt$(patsubst -%,%,$(TRUSTED_OPT))-$(TRUSTED_CORE)
ifneq ($(ENCLAVE_BASE),0x40000000)
BUILD := $(BUILD)-base$(patsubst 0x%,%,$(ENCLAVE_BASE))
endif
E := $(BUILD)/enclave
H := $(BUILD)/host
G := $(BUILD)/generated
P := $(BUILD)/prepared
export ENCBOUND_CXX_HEADERS := $(BUILD)/core-headers
SDKLIB := $(SGX_SDK)/lib64
GENERATOR := $(ROOT)/build/edger8r/sgx_edger8r
PLUGIN ?= $(ROOT)/build/pass/encbound_pass.so
export ENCBOUND_PLUGIN := $(PLUGIN)
COMMON := -m64 -O0 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
INCLUDES := -I$(HERE) -I$(P) -I$(G) -I$(ROOT)/include -I$(ROOT)/runtime -I$(ROOT)/sdk \
 -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -isystem $(PINNED_SRC)/common/inc/internal
EFLAGS := $(COMMON) $(INCLUDES) -nostdinc -fvisibility=hidden -fpie \
 -ffunction-sections -fdata-sections -fstack-protector-strong $(MITIGATION_CFLAGS) -MMD -MP
DEFINES :=
APP := Enclave
TRUSTED := enclave_t cxx_services entropy
ifeq ($(PROFILE),BASELINE)
DEFINES += -DENCBOUND_CXX_BASELINE
else
DEFINES += -DENCBOUND_PROTECTED
TRUSTED += boundary_support platform_layout siphash runtime capability allocations allocator adapters early_bootstrap cxx_lifecycle
ifeq ($(TRUSTED_CORE),fused)
TRUSTED := $(filter-out siphash runtime capability,$(TRUSTED)) check_core
endif
endif
ifeq ($(PROFILE),MAC27)
DEFINES += -DENCBOUND_MAC27
endif
CXX_SDK_LIBRARY :=
ifeq ($(ENCBOUND_CXX_LIFECYCLE),1)
CXX_SDK_LIBRARY := -lsgx_tcxx
endif
OBJS := $(addprefix $(E)/,$(addsuffix .o,$(APP) $(TRUSTED)))
ifeq ($(PROFILE),BASELINE)
OBJS := $(filter-out $(E)/early_bootstrap.o $(E)/cxx_lifecycle.o,$(OBJS))
else
OBJS := $(E)/early_bootstrap.o $(filter-out $(E)/early_bootstrap.o,$(OBJS))
endif
GEN := $(addprefix $(G)/,Enclave_t.c Enclave_t.h Enclave_u.c Enclave_u.h Enclave_app.c Enclave_app.h admitted-app.txt admitted-ocalls.txt boundary-manifest.json)

LINK := $(MITIGATION_LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack -Wl,--no-undefined \
 -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
 -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
 -Wl,--start-group $(CXX_SDK_LIBRARY) -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
 -Wl,-Bstatic -Wl,-Bsymbolic -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
 -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
 -Wl,--version-script=$(ROOT)/sdk/enclave.lds -Wl,-T,$(ROOT)/sdk/enclave_sections.lds
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.PHONY: all audit pins clean vuln-host FORCE
all: audit
$(E) $(H) $(G) $(P):
	mkdir -p $@
$(GENERATOR): $(wildcard $(ROOT)/tools/edger8r/*.ml $(ROOT)/tools/edger8r/*.mll $(ROOT)/tools/edger8r/*.mly) $(ROOT)/tools/edger8r/Makefile
	$(MAKE) -C $(ROOT)/tools/edger8r
$(PLUGIN): $(ROOT)/pass/encbound_pass.cpp $(ROOT)/pass/encbound_fast_paths.h $(ROOT)/pass/encbound_integration.h $(ROOT)/pass/encbound_globals.h $(ROOT)/pass/encbound_lifecycle.h $(ROOT)/pass/encbound_vla.h $(ROOT)/pass/encbound_cxx_eh.h $(ROOT)/pass/Makefile
	$(MAKE) -C $(ROOT)/pass
$(P)/prepared.json $(P)/Enclave.cpp $(P)/Enclave.edl &: $(HERE)/prepare.py $(HERE)/pins.json | $(P)
	python3 $(HERE)/prepare.py --source $(SOURCE) --out $(BUILD)/prepared
$(GEN) &: $(P)/prepared.json $(HERE)/boundary-interface.json $(ROOT)/tools/modified_bridge.py $(GENERATOR) $(ROOT)/sdk/modified_bridge.h | $(G)
	python3 $(ROOT)/tools/modified_bridge.py --edl $(P)/Enclave.edl --interface $(HERE)/boundary-interface.json \
	 --generator $(GENERATOR) --out-dir $(G) --profile $(PROFILE) --search-path $(SGX_SDK)/include \
	 --cc $(CC) --layout-cc clang-21 $(addprefix --cflag=,$(INCLUDES) -nostdinc)

define app_compile
	$(ROOT)/tools/encbound-cxx.sh $< $@ $(EFLAGS) -fno-common -fno-builtin -include $(BUILD)/libc-format/namespace.h -O2
	ENCBOUND_WRITABLE_GLOBALS=1 $(ROOT)/tools/mark_appdata_sections.sh $@ $@.placed
	mv $@.placed $@
	mv $@.placed.ownership.json $@.ownership.json
endef
$(E)/Enclave.o: $(P)/Enclave.cpp $(GEN) $(PLUGIN) $(BUILD)/admitted.txt | $(E)
	$(app_compile)
$(E)/entropy.o: $(HERE)/entropy.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/enclave_t.o: $(G)/Enclave_t.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/early_bootstrap.o: $(ROOT)/sdk/early_bootstrap.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/boundary_support.o: $(ROOT)/sdk/boundary_support.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/platform_layout.o: $(ROOT)/sdk/platform_layout.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/%.o: $(ROOT)/runtime/%.c $(GEN) | $(E)
	$(CC) $(EFLAGS) $(TRUSTED_OPT) $(DEFINES) -c $< -o $@
$(E)/enclave.so: $(OBJS) $(BUILD)/libc-format/libencbound_format.a $(ROOT)/sdk/enclave.lds $(ROOT)/sdk/enclave_sections.lds $(ROOT)/apps/four_app_audit.py
	$(CC) $(OBJS) $(shell cat $(BUILD)/library-objects.txt) -o $@ $(LINK) -Wl,-Map,$(E)/enclave.map
	python3 $(ROOT)/apps/four_app_audit.py record-link $(BUILD)
$(BUILD)/test-key.pem: | $(E)
	openssl genrsa -out $@ -3 3072
$(BUILD)/sizing.xml: $(HERE)/enclave.config.tmpl.xml $(ROOT)/tools/sgx_metadata.py | $(E)
	python3 $(ROOT)/tools/sgx_metadata.py render-config --template $< --base $(ENCLAVE_BASE) --size 0x40000000 --out $@
$(BUILD)/sizing.so: $(E)/enclave.so $(BUILD)/sizing.xml $(BUILD)/test-key.pem
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config $(BUILD)/sizing.xml
$(BUILD)/extent: $(BUILD)/sizing.so
	python3 $(ROOT)/tools/sgx_metadata.py required --signed $< > $@
$(BUILD)/final.xml: $(HERE)/enclave.config.tmpl.xml $(BUILD)/extent
	python3 $(ROOT)/tools/sgx_metadata.py render-config --template $< --base $(ENCLAVE_BASE) --size "$$(cat $(BUILD)/extent)" --out $@
$(E)/enclave.signed.so: $(E)/enclave.so $(BUILD)/final.xml $(BUILD)/test-key.pem
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(BUILD)/test-key.pem -enclave $< -out $@ -config $(BUILD)/final.xml
	python3 $(ROOT)/tools/sgx_metadata.py verify --signed $@ --base $(ENCLAVE_BASE) --size "$$(cat $(BUILD)/extent)"
$(H)/host.o: $(HERE)/host.c $(GEN) | $(H)
	$(CC) $(COMMON) -I$(P) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/Enclave_u.o: $(G)/Enclave_u.c $(GEN) | $(H)
	$(CC) $(COMMON) -I$(P) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/host: $(H)/host.o $(H)/Enclave_u.o
	$(CC) $^ -o $@ -L$(SDKLIB) -Wl,-rpath-link,$(SDKLIB) -L$(SGX_SDK)/sdk_libs -lsgx_urts_sim -lpthread -lcrypto -lm
# Separate hostile-shape control; the functional host and its evidence stay
# unchanged. Built explicitly by apps/conflow/vuln.py.
vuln-host: $(H)/vuln-host
$(H)/vuln_host.o: $(HERE)/vuln_host.c $(GEN) | $(H)
	$(CC) $(COMMON) -I$(P) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/vuln-host: $(H)/vuln_host.o $(H)/Enclave_u.o
	$(CC) $^ -o $@ -L$(SDKLIB) -Wl,-rpath-link,$(SDKLIB) -L$(SGX_SDK)/sdk_libs -lsgx_urts_sim -lpthread -lcrypto -lm
# Separate direct [user_check] pointer-forgery control; the functional and
# hostile-shape hosts above stay unchanged. Built by apps/conflow/confused_deputy.py.
cd-host: $(H)/cd-host
$(H)/confused_deputy_host.o: $(HERE)/confused_deputy_host.c $(GEN) | $(H)
	$(CC) $(COMMON) -I$(P) -I$(G) -I$(SGX_SDK)/include -MMD -MP -c $< -o $@
$(H)/cd-host: $(H)/confused_deputy_host.o $(H)/Enclave_u.o
	$(CC) $^ -o $@ -L$(SDKLIB) -Wl,-rpath-link,$(SDKLIB) -L$(SGX_SDK)/sdk_libs -lsgx_urts_sim -lpthread -lcrypto -lm
pins: $(P)/prepared.json
	python3 $(ROOT)/tools/check_sdk_pins.py --sdk $(SGX_SDK) --pinned $(PINNED_SRC)
audit: $(H)/host $(E)/enclave.signed.so pins
	python3 $(HERE)/audit.py --build $(BUILD) --profile $(PROFILE) --base $(ENCLAVE_BASE) --sdk $(SGX_SDK)
clean:
	rm -rf $(BUILD)
FORCE:
$(BUILD)/build-config.json: FORCE | $(E)
	python3 -c 'import json,pathlib; p=pathlib.Path("$@"); s=json.dumps(dict(app="conflow",profile="$(PROFILE)",base="$(ENCLAVE_BASE)",codegen="$(APP_CODEGEN_OPT)",trusted_opt="$(TRUSTED_OPT)",trusted_core="$(TRUSTED_CORE)",preset="$(ENCBOUND_INTEGRATION_PRESET)"),sort_keys=True)+"\n"; p.write_text(s) if not p.exists() or p.read_text()!=s else None'
$(OBJS) $(H)/host.o $(H)/vuln_host.o $(H)/confused_deputy_host.o $(H)/Enclave_u.o: Makefile $(BUILD)/build-config.json
-include $(wildcard $(E)/*.d $(H)/*.d) $(G)/boundary.d

$(filter-out $(addprefix $(E)/,$(addsuffix .o,$(TRUSTED))),$(OBJS)): $(ROOT)/config/integration.env $(ROOT)/tools/encbound-cc.sh $(ROOT)/tools/record_integration_unit.py

$(BUILD)/libraries.stamp: $(P)/prepared.json $(GEN) $(HERE)/libc-pins.json $(HERE)/libraries.py $(ROOT)/config/integration.env $(PLUGIN) \
 $(ROOT)/apps/libc-format/build.py $(ROOT)/apps/libc-format/pins.json $(ROOT)/apps/libc-format/helpers.c \
 $(ROOT)/tools/prepare_cxx_headers.py $(ROOT)/tools/encbound-cc.sh $(ROOT)/tools/record_integration_unit.py \
 $(ROOT)/tools/mark_appdata_sections.sh $(ROOT)/tools/mark_app_globals.py
	python3 $(HERE)/libraries.py --build $(BUILD) --profile $(PROFILE) --sdk $(SGX_SDK) --sdk-source $(PINNED_SRC)
	touch $@
$(BUILD)/admitted.txt $(BUILD)/libc-format/libencbound_format.a: $(BUILD)/libraries.stamp
	test -f $@
