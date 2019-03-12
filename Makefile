INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := duo_openvpn_mozilla
VERSION := 1.1.0
.DEFAULT: test
.PHONY: test coverage coveragereport pyinstall pep8 pylint pythonrpm pluginrpm rpm deb pypi install clean
TEST_FLAGS_FOR_SUITE := -m unittest discover -v -f -s test

# Testing is deliberately verbose because we will skip tests based on the
# capabilities of the user being tested's device
test:
	# If you are seeing a lot of skips, consider editing the deep_testing flags in your conf file.
	python -B $(TEST_FLAGS_FOR_SUITE)

coverage:
	coverage run $(TEST_FLAGS_FOR_SUITE)
	@rm -f $(PACKAGE)/*.pyc test/*.pyc

coveragereport:
	coverage report -m $(PACKAGE)/*.py test/*.py


pyinstall:
	./setup.py install

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 --show-source --max-line-length=100 {} \;

pylint:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pylint -r no --disable=locally-disabled --rcfile=/dev/null {} \;

pythonrpm:
	fpm -s python -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

# FIXME: summary  description   git?
pluginrpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" \
    -d python-duo-openvpn-mozilla -d openvpn_defer_auth \
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

clean:
	rm -f *.pyc test/*.pyc $(PACKAGE)/*.pyc
	rm -rf __pycache__
	rm -rf dist sdist build
	rm -rf $(PACKAGE).egg-info
	rm -rf tmp
