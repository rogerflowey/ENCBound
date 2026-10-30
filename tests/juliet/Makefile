# Diagnostic SIM recipe, reduced from sdk/Makefile (Intel BSD-3-Clause sample
# ancestry recorded there). Application objects are built/audited by juliet.py.
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
ROOT := $(abspath ../..)
SGX_SDK ?= $(abspath ../../deps/sgxsdk)
PINNED_SRC ?= $(abspath ../../deps/intel-sgx)
ifndef OUT
$(error OUT is required)
endif
ifeq ($(filter $(PROFILE),BASELINE RADIX_ONLY MAC27),)
$(error PROFILE must be BASELINE, RADIX_ONLY or MAC27)
endif
include $(SGX_SDK)/buildenv.mk
CC := gcc
LIB := $(SGX_SDK)/lib64
EFLAGS := -m64 -O0 -g -fpie -fvisibility=hidden -ffunction-sections -fdata-sections \
 -fstack-protector-strong -nostdinc -MMD -MP -I$(OUT) -I$(ROOT)/include \
 -I$(ROOT)/runtime -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
 -isystem $(PINNED_SRC)/common/inc/internal $(MITIGATION_CFLAGS)
ifeq ($(PROFILE),MAC27)
EFLAGS += -DENCBOUND_MAC27
endif
ifeq ($(PROFILE),BASELINE)
EFLAGS += -DJULIET_BASELINE
RUNTIME :=
else
RUNTIME := platform_layout siphash runtime capability allocations allocator adapters
endif
TRUSTED := $(addprefix $(OUT)/,$(addsuffix .o,$(RUNTIME))) $(OUT)/entry.o $(OUT)/juliet_t.o
HOSTFLAGS := -m64 -O0 -g -fPIC -I$(OUT) -I$(SGX_SDK)/include
LINK := $(MITIGATION_LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack \
 -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_TRUSTED_LIBRARY_PATH) \
 -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
 -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
 -Wl,-Bstatic -Wl,-Bsymbolic -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
 -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections -Wl,-Map,$(OUT)/enclave.map \
 -Wl,-T,$(ROOT)/sdk/enclave_sections.lds -Wl,--version-script=$(ROOT)/sdk/enclave.lds
META := $(ROOT)/tools/sgx_metadata.py
SIGN := $(SGX_SDK)/bin/x64/sgx_sign
APP_OBJECTS := $(shell cat $(OUT)/objects.txt)

.PHONY: all pins audit
all: pins $(OUT)/host $(OUT)/enclave.signed.so audit
pins:
	python3 $(ROOT)/tools/check_sdk_pins.py --sdk $(SGX_SDK) --pinned $(PINNED_SRC)
$(OUT)/juliet_t.c $(OUT)/juliet_t.h $(OUT)/juliet_u.c $(OUT)/juliet_u.h &: juliet.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --search-path $(SGX_SDK)/include --trusted --trusted-dir $(OUT) --untrusted --untrusted-dir $(OUT) $<
$(OUT)/host.o: host.c $(OUT)/juliet_u.h Makefile
	$(CC) $(HOSTFLAGS) -c $< -o $@
$(OUT)/juliet_u.o: $(OUT)/juliet_u.c
	$(CC) $(HOSTFLAGS) -c $< -o $@
$(OUT)/host: $(OUT)/host.o $(OUT)/juliet_u.o
	$(CC) $^ -o $@ -L$(LIB) -Wl,-rpath-link,$(LIB) -lsgx_urts_sim -lpthread
$(OUT)/entry.o: entry.c $(OUT)/juliet_t.h Makefile
	$(CC) $(EFLAGS) -c $< -o $@
$(OUT)/juliet_t.o: $(OUT)/juliet_t.c
	$(CC) $(EFLAGS) -c $< -o $@
$(OUT)/platform_layout.o: $(ROOT)/sdk/platform_layout.c Makefile
	$(CC) $(EFLAGS) -c $< -o $@
$(OUT)/%.o: $(ROOT)/runtime/%.c Makefile
	$(CC) $(EFLAGS) -c $< -o $@
$(OUT)/enclave.so: $(TRUSTED) $(APP_OBJECTS) $(OUT)/objects.txt $(ROOT)/sdk/enclave_sections.lds $(ROOT)/sdk/enclave.lds
	$(CC) $(TRUSTED) $(APP_OBJECTS) -o $@ $(LINK)
$(OUT)/key.pem:
	openssl genrsa -out $@ -3 3072
$(OUT)/sizing.xml: $(ROOT)/sdk/enclave.config.tmpl.xml $(META)
	python3 $(META) render-config --template $< --base 0x40000000 --size 0x40000000 --out $@
$(OUT)/sizing.so: $(OUT)/enclave.so $(OUT)/sizing.xml $(OUT)/key.pem
	$(SIGN) sign -key $(OUT)/key.pem -enclave $< -out $@ -config $(OUT)/sizing.xml
$(OUT)/extent: $(OUT)/sizing.so
	python3 $(META) required --signed $< > $@
$(OUT)/final.xml: $(OUT)/extent $(ROOT)/sdk/enclave.config.tmpl.xml $(META)
	python3 $(META) render-config --template $(ROOT)/sdk/enclave.config.tmpl.xml --base 0x40000000 --size "$$(cat $<)" --out $@
$(OUT)/enclave.signed.so: $(OUT)/enclave.so $(OUT)/final.xml $(OUT)/key.pem
	$(SIGN) sign -key $(OUT)/key.pem -enclave $< -out $@ -config $(OUT)/final.xml
	python3 $(META) verify --signed $@ --base 0x40000000 --size "$$(cat $(OUT)/extent)"
audit: $(OUT)/enclave.signed.so
	python3 $(ROOT)/tools/check_sdk_pins.py --sdk $(SGX_SDK) --pinned $(PINNED_SRC) --link-map $(OUT)/enclave.map
	@for obj in $(TRUSTED); do python3 $(ROOT)/tools/encbound_inventory.py audit --object $$obj --expect trusted || exit 1; done
-include $(wildcard $(OUT)/*.d)
