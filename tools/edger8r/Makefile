ROOT := $(abspath ../..)
BUILD := $(ROOT)/build/edger8r
SOURCES := $(wildcard *.ml *.mll *.mly)
.PHONY: all
all: $(BUILD)/sgx_edger8r
$(BUILD)/sgx_edger8r: $(SOURCES) Makefile upstream.json
	mkdir -p $(BUILD)
	cp $(SOURCES) $(BUILD)/
	cd $(BUILD) && ocamlbuild -cflags -ccopt,-fpie -lflags -runtime-variant,_pic,-ccopt,-pie,-ccopt -lflag '-Wl,-z,now' -no-links -libs str,unix Edger8r.native
	cp $(BUILD)/_build/Edger8r.native $@
