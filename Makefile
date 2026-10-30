.PHONY: all test bridge-test compatibility-test smoke sources verify juliet-test juliet
all:
	$(MAKE) -C pass
	$(MAKE) -C tools/edger8r

test: all
	$(MAKE) -C tests run
	$(MAKE) -C pass test
	python3 tests/sdk_pins_test.py

bridge-test: all
	$(MAKE) -C tests edl-check

compatibility-test: all
	python3 tests/cxx-lifecycle/admission.py
	python3 tests/cxx-lifecycle/native.py
	python3 tests/cxx-eh-rtti/run.py --profile MAC27 --frontend O2
	python3 tests/cxx-eh-rtti/admission.py
	python3 tests/cxx-eh-rtti/native.py
	python3 tests/errno/run.py --native-only

smoke: all
	python3 apps/conflow/run.py

sources:
	python3 tools/prepare-paper-sources.py

juliet-test:
	python3 tests/juliet/oracle_test.py

JULIET_ARCHIVE ?= $(CURDIR)/build/juliet/download/juliet-1.3.zip
juliet: all juliet-test
	python3 tools/juliet.py --archive "$(JULIET_ARCHIVE)"

verify:
	sha256sum -c MANIFEST.sha256
