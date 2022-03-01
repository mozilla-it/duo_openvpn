INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := duo_openvpn_mozilla
VERSION := 1.4.2
.DEFAULT: test
.PHONY: test coverage coveragereport pyinstall pep8 pylint pythonrpm pluginrpm rpm pythonrpm pythonrpm2 pythonrpm3 deb pypi install clean
TEST_FLAGS_FOR_SUITE := -m unittest discover -f

PLAIN_PYTHON = $(shell which python 2>/dev/null)
PYTHON3 = $(shell which python3 2>/dev/null)
ifneq (, $(PYTHON3))
  PYTHON_BIN = $(PYTHON3)
  PY_PACKAGE_PREFIX = python3
  RPM_MAKE_TARGET = pythonrpm3
endif
ifneq (, $(PLAIN_PYTHON))
  PYTHON_BIN = $(PLAIN_PYTHON)
  PY_PACKAGE_PREFIX = python
  RPM_MAKE_TARGET = pythonrpm2
endif

COVERAGE2 = $(shell which coverage 2>/dev/null)
COVERAGE3 = $(shell which coverage-3 2>/dev/null)
ifneq (, $(COVERAGE2))
  COVERAGE = $(COVERAGE2)
endif
ifneq (, $(COVERAGE3))
  COVERAGE = $(COVERAGE3)
endif

# Testing is deliberately verbose because we will skip tests based on the
# capabilities of the user being tested's device
test:
	# If you are seeing a lot of skips, consider editing the deep_testing flags in your conf file.
	$(COVERAGE) run $(TEST_FLAGS_FOR_SUITE) -v -s test/integration
	@rm -rf test/integration/__pycache__
	@rm -f test/*.pyc test/*/*.pyc

testreport:
	$(COVERAGE) report -m $(PACKAGE)/*.py test/integration/*.py

coverage:
	$(COVERAGE) run $(TEST_FLAGS_FOR_SUITE) -s test/unit
	@rm -rf test/unit/__pycache__
	@rm -f $(PACKAGE)/*.pyc test/*.pyc test/*/*.pyc

coveragereport:
	$(COVERAGE) report -m duo_openvpn.py $(PACKAGE)/*.py test/unit/*.py

pyinstall:
	./setup.py install

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 --show-source --max-line-length=100 {} \;

pylint:
	@find ./$(PACKAGE) -path ./test -prune -o -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,superfluous-parens --rcfile=/dev/null {} \;
	@find ./test -type f -name '*.py' -exec pylint -r no --disable=useless-object-inheritance,protected-access,locally-disabled,inconsistent-return-statements --rcfile=/dev/null {} \;

pythonrpm:  $(RPM_MAKE_TARGET)

pythonrpm2:
	fpm -s python -t rpm --python-bin $(PYTHON_BIN) --python-package-name-prefix $(PY_PACKAGE_PREFIX) --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

pythonrpm3:
	fpm -s python -t rpm --python-bin $(PYTHON_BIN) --python-package-name-prefix $(PY_PACKAGE_PREFIX) --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

# FIXME: summary  description   git?
pluginrpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d "$(PY_PACKAGE_PREFIX)-duo-openvpn-mozilla >= 1.4.1" -d openvpn_defer_auth \
    -n duo_openvpn-mozilla -v $(VERSION) \
    --url https://github.com/mozilla-it/duo_openvpn \
    -a noarch -C tmp usr
	@rm -rf ./tmp

rpm: pythonrpm pluginrpm

deb:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t deb -n $(PACKAGE) -v $(VERSION) -C tmp usr

pypi:
	python setup.py sdist check upload --sign

install:
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 duo_openvpn.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	sed -i "1c#! $(PYTHON_BIN)" $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/duo_openvpn.py

clean:
	rm -f *.pyc test/*.pyc $(PACKAGE)/*.pyc
	rm -rf __pycache__
	rm -rf dist sdist build
	rm -rf $(PACKAGE).egg-info
	rm -rf tmp
