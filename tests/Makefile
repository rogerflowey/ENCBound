#
# ENCBound restart - native runtime tests (fake platform).
# Builds the same runtime in MAC27 and RADIX_ONLY profiles.
#
# Run as: make -C tests run
#         make -C tests edl-check
#

ROOT := $(abspath $(CURDIR)/..)
CC ?= clang
# Pinned Clang for the record-layout AST probe; the ABI syntax check uses $(CC).
LAYOUT_CC ?= clang-21
PYTHON ?= python3
SGX_SDK ?= $(ROOT)/deps/sgxsdk
CFLAGS := -O1 -g -Wall -Wextra -Wno-unused-parameter -MMD -MP \
          -I$(ROOT)/include -I$(ROOT)/runtime -I$(ROOT)/wrappers -I$(CURDIR)
SDK_CFLAGS := $(CFLAGS) -I$(SGX_SDK)/include
BUILD := $(ROOT)/build/tests

RT_SRC := $(ROOT)/runtime/siphash.c $(ROOT)/runtime/runtime.c \
          $(ROOT)/runtime/capability.c $(ROOT)/runtime/allocations.c \
          $(ROOT)/runtime/allocator.c $(ROOT)/runtime/adapters.c
RT_TEST_SRC := $(CURDIR)/fake_platform.c $(CURDIR)/runtime_test.c
AD_TEST_SRC := $(CURDIR)/fake_platform.c $(CURDIR)/adapters_test.c
SDK_AD_SRC := $(CURDIR)/fake_platform.c $(CURDIR)/sdk_adapters_test.c \
              $(ROOT)/wrappers/sdk_adapters.c

SESSION_TEST_SRC := $(CURDIR)/session_test.c $(CURDIR)/fake_platform.c $(ROOT)/sdk/boundary_support.c
SESSION_FLAGS := $(SDK_CFLAGS) -I$(ROOT)/sdk -DENCBOUND_PROTECTED
ALLOCATOR_TEST_LINK := -Wl,--wrap=malloc -Wl,--wrap=free
NAMES := runtime_test allocator_test adapters_test sdk_adapters_test session_test
BINARIES := $(foreach n,$(NAMES),$(BUILD)/$(n)_mac27 $(BUILD)/$(n)_radix)
.PHONY: all run edl-check clean
all: $(BINARIES)
# Each test binary is linked from per-object compilations so every translation
# unit retains its own header dependency file (static review R3, 2026-10-06).
define TEST_OBJ
$(BUILD)/$(1)-$(notdir $(2:.c=.o)): $(2) $(MAKEFILE_LIST) | $(BUILD) $(4)
	$(CC) $(3) -c $(2) -o $$@
endef

# $(call TEST_BIN,<name>,<compile flags>,<sources>[,<generated prerequisites>[,<link flags>]])
define TEST_BIN
$(BUILD)/$(1): $(foreach s,$(3),$(BUILD)/$(1)-$(notdir $(s:.c=.o)))
	$(CC) $$^ -o $$@ $(5)
$(foreach s,$(3),$(eval $(call TEST_OBJ,$(1),$(s),$(2),$(4))))
endef

$(eval $(call TEST_BIN,runtime_test_mac27,$(CFLAGS) -DENCBOUND_MAC27,$(RT_SRC) $(RT_TEST_SRC)))
$(eval $(call TEST_BIN,runtime_test_radix,$(CFLAGS),$(RT_SRC) $(RT_TEST_SRC)))
$(eval $(call TEST_BIN,allocator_test_mac27,$(CFLAGS) -DENCBOUND_MAC27,$(RT_SRC) $(CURDIR)/fake_platform.c $(CURDIR)/allocator_test.c,,$(ALLOCATOR_TEST_LINK)))
$(eval $(call TEST_BIN,allocator_test_radix,$(CFLAGS),$(RT_SRC) $(CURDIR)/fake_platform.c $(CURDIR)/allocator_test.c,,$(ALLOCATOR_TEST_LINK)))
$(eval $(call TEST_BIN,adapters_test_mac27,$(CFLAGS) -DENCBOUND_MAC27,$(RT_SRC) $(AD_TEST_SRC)))
$(eval $(call TEST_BIN,adapters_test_radix,$(CFLAGS),$(RT_SRC) $(AD_TEST_SRC)))
$(eval $(call TEST_BIN,sdk_adapters_test_mac27,$(SDK_CFLAGS) -DENCBOUND_MAC27,$(RT_SRC) $(SDK_AD_SRC)))
$(eval $(call TEST_BIN,sdk_adapters_test_radix,$(SDK_CFLAGS),$(RT_SRC) $(SDK_AD_SRC)))
$(eval $(call TEST_BIN,session_test_mac27,$(SESSION_FLAGS) -DENCBOUND_MAC27,$(RT_SRC) $(SESSION_TEST_SRC)))
$(eval $(call TEST_BIN,session_test_radix,$(SESSION_FLAGS),$(RT_SRC) $(SESSION_TEST_SRC)))

$(BUILD):
	mkdir -p $@

run: all
	$(BUILD)/allocator_test_mac27
	$(BUILD)/allocator_test_radix
	$(BUILD)/runtime_test_mac27
	$(BUILD)/runtime_test_radix
	$(BUILD)/adapters_test_mac27
	$(BUILD)/adapters_test_radix
	$(BUILD)/sdk_adapters_test_mac27
	$(BUILD)/sdk_adapters_test_radix
	$(PYTHON) $(CURDIR)/modified_bridge_test.py
	$(BUILD)/session_test_mac27
	$(BUILD)/session_test_radix

edl-check:
	$(MAKE) -C $(ROOT)/pass all
	$(MAKE) -C $(ROOT)/tools/edger8r all
	$(PYTHON) $(CURDIR)/modified_bridge_test.py
	$(PYTHON) $(CURDIR)/integration/user_check_test.py
	$(PYTHON) $(CURDIR)/integration/user_check_ocall_test.py
	$(PYTHON) $(CURDIR)/integration/edger8r_admission_test.py
	$(PYTHON) $(CURDIR)/integration/edl_imports_test.py
	$(PYTHON) $(CURDIR)/integration/sdk_ecalls_test.py
	$(PYTHON) $(CURDIR)/integration/edl_transport_admission_test.py
	$(PYTHON) $(CURDIR)/integration/edl_shallow_test.py
	$(PYTHON) $(CURDIR)/integration/edl_buffers_test.py
	$(PYTHON) $(CURDIR)/integration/edl_buffers_test.py --application-imports
	$(PYTHON) $(CURDIR)/integration/edl_records_test.py


clean:
	rm -rf $(BUILD)
