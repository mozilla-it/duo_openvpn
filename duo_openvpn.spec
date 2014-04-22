%define		prefix	/usr

Name:		duo_openvpn-mozilla	
Version:	1.0		
Release:	1%{?dist}
Packager:	Ed Lim <limed@mozilla.com>
Summary:	Duo plugin for OpenVPN mozilla style
	
Group:		Utilities/Misc		
License:	MPL
URL:		https://duosecurity.com
Source0:	duo_openvpn-mozilla-%{version}.tar.gz
BuildRoot:  %{_tmppath}/%{name}-root
Requires:	python, python-duo_client python-mozdef	

%description
Duo provides a simple two-factor as a service via:

* Phone callback
* SMS-delivered one-time passcodes
* Duo mobile app to generate one-time passcodes
* Duo mobile app for smartphone push authentication
* Duo hardware token to generate one-time passcodes

This package provides the OpenVPN authentication plugin and scripts.
However this package is created by Mozilla to enable extra LDAP lookups, and
can also serve as an LDAP authentication plugin.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}

%files
%defattr(0755,root,root)
%{prefix}/lib/openvpn/plugins/duo_openvpn.so
%{prefix}/lib/openvpn/plugins/duo_openvpn.py
%{prefix}/lib/openvpn/plugins/duo_openvpn.pyc
%{prefix}/lib/openvpn/plugins/duo_openvpn.pyo
%attr(0644,root,root) %config(noreplace) %verify(not md5 size mtime)/etc/duo_openvpn.conf

%changelog
* Wed Apr 16 2014 Ed Lim <limed@mozilla.com>
- Initial creation of spec file
