%define		debug_package %{nil}
%define		prefix	/usr
%define		shortname	duo_openvpn

Name:		%{shortname}-mozilla
Version:	1.0.4
Release:	1%{?dist}
Packager:	Greg Cox <gcox@mozilla.com>
Summary:	Duo authentication plugin for Mozilla-style OpenVPN

Group:		Utilities/Misc
License:	MPL
URL:		https://github.com/mozilla-it/%{shortname}
Source0:	https://github.com/mozilla-it/%{shortname}/archive/master.zip
BuildRoot:	%(mktemp -ud %{_tmppath}/%{shortname}-%{version}-%{release}-XXXXXX)
Requires:	python, python-duo_client python-mozdef_client, openvpn_defer_auth

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
%setup -q -n %{shortname}-master

%build
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}


%clean
rm -rf %{buildroot}

%files
%defattr(0755,root,root)
%{prefix}/lib/openvpn/plugins/duo_openvpn.py
%{prefix}/lib/openvpn/plugins/duo_openvpn.pyc
%exclude %{prefix}/lib/openvpn/plugins/duo_openvpn.pyo
%attr(0600,root,root) %config(noreplace) %verify(not md5 size mtime)/etc/duo_openvpn.conf

%changelog
* Thu Mar  8 2018 gcox <gcox@mozilla.com>
    - Better permissions on the file that could ostensibly contain passwords

* Mon Feb 12 2018 gcox <gcox@mozilla.com>
    - Stop packaging .pyo because PEP 488
    - Build based on a github checkout

* Wed Apr 16 2014 Ed Lim <limed@mozilla.com>
- Initial creation of spec file
