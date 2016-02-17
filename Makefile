CC	:= gcc
CFLAGS	:=
LDFLAGS	:= -fPIC -shared
INSTALL	:= install
DESTDIR	:= /
PREFIX	:= /usr
PACKAGE := duo_openvpn
VERSION := 1.0.3

all: plugin
	./setup.py build

pyinstall:
	./setup.py install

rpm:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t rpm -d python-mozdef_client -n $(PACKAGE) -v $(VERSION) -C tmp etc usr

deb:
	$(MAKE) DESTDIR=./tmp install
	fpm -s dir -t deb -d python-mozdef_client -n $(PACKAGE) -v $(VERSION) -C tmp etc usr

pypi:
	python setup.py sdist check upload --sign

plugin: duo_openvpn.c
	$(CC) $(CFLAGS) $(LDFLAGS) -I. -c duo_openvpn.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,duo_openvpn.so -o duo_openvpn.so duo_openvpn.o

install: plugin
	mkdir -p $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	mkdir -p $(DESTDIR)/etc/openvpn/
	$(INSTALL) -m755 duo_openvpn.so $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m755 duo_openvpn.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/
	$(INSTALL) -m600 duo_openvpn.conf.inc $(DESTDIR)/etc/duo_openvpn.conf
	$(INSTALL) -m755 scripts/vpn_kill_users.py $(DESTDIR)$(PREFIX)/lib/openvpn/plugins/

clean:
	rm -f *.o
	rm -f *.so
	rm -f *.pyc
	rm -rf __pycache__
	rm -rf dist sdist build
	rm -rf $(PACKAGE).egg-info
	rm -rf tmp
	rm -rf *.rpm
	rm -rf *.deb
