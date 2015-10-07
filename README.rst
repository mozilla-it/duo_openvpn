===========
Duo_openvpn
===========

.. image:: https://travis-ci.org/mozilla-it/duo_openvpn.svg?branch=master
    :target: https://travis-ci.org/mozilla-it/duo_openvpn

Our own take at duo_openvpn support.
Not very happy with the provided duo_openvpn support, we rewrote it to use duo_client_python which is much nicer.

Git submodules
--------------

In order to checkout all the modules necessary for this to build, run

.. code::

	git clone --recursive git@github.com:mozilla-it/duo_openvpn.git
	# Or, if already checked out:
	git submodule update --init --recursive

Features
--------

- Simple. Sort of. The LDAP features are a little more complex - if you don't use that, it's fairly simple.
- Auth caching per login+ip address.
- Fail open (optional).
- OTP and Push (use push as password for push, passcode:123456 as password for OTP, where 123456 is your OTP).
- CEF support.
- MozDef support.
- Optional username hack, in case you use emails as certificate CN but only the first part of the email as login.
- Supports logging with LDAP with or instead-of Duo.
- Deferred call.

Configuration
-------------

C plugin
~~~~~~~~
Call it from openvpn configuration with:

.. code::

   plugin /usr/lib/openvpn/plugins/duo_openvpn.so /usr/lib/openvpn/plugins/duo_openvpn.py

This allow making a deferred call for authentication while using a script instead of blocking OpenVPN.
This is needed as otherwise Duo will block OpenVPN while waiting for a push reply or OTP input.

Python script
~~~~~~~~~~~~~
Look at duo_openvpn.conf.inc and rename/copy it to duo_openvpn.conf (or /etc/duo_openvpn.conf). Here are some examples & help:

:TRY_LDAP_ONLY_AUTH_FIRST=False: Try to auth LDAP first, if succeeds, bypass DuoSec.
:LDAP_URL="ldap://ldap.db.scl3.mozilla.com": Needed for any LDAP operation, else leave empty.
:LDAP_BIND_DN='mail=%s,o=com,dc=mozilla': The bind dn for the user auth. %s is replaced by the username.
:LDAP_BASE_DN='dc=mozilla': The base dn to find the user to auth in.

LDAP control values are mainly used to filter on a group that has DuoSecurity enabled. If you're in that group, you get DuoSec, else, you get LDAP auth.
Basically, we're looking up the user's uid from his email (as we're passed an email as common_name). If the uid == the email, that's fine too.
Then, we lookup for an attribute in LDAP, and we check that the attribute's value's value (yeah..) == the uid. Looks like this:
User: mail=hi@mozilla.com,o=com,dc=mozilla => uid = hi
Attributes: {'posix_sysadmins': {'memberUid': "user1", "hi", "user2, ... }}

:LDAP_CONTROL_BIND_DN="uid=bind-openvpn,ou=logins,dc=mozilla": Bind to that user for attribute checks.
:LDAP_CONTROL_PASSWORD="": The password for the above user.
:LDAP_CONTROL_BASE_DN="ou=groups,dc=mozilla": The base DN for the above attribute search.
:LDAP_NO_DUOSEC_ATTR_VALUE="cn=posix_sysadmins": Will look for that attribute, to see if you should bypass Duo authentication.
:LDAP_DUOSEC_ATTR="memberUid": Will look for that value in the attribute.

Misc scripts
~~~~~~~~~~~~
The /scripts directory contains additional goodies.

vpn_kill_users
===============
If you use reneg-sec 0 as setting so that OpenVPN does not renegociate (or renegociates very rarely should you use
another setting than 0 but that is still very high), you might still want to automatically disconnect users that you
have disabled in LDAP.

Run this in a crontab periodically, it'll pool for the users and kill em.

Recommended openvpn server settings:

.. code::

   management /var/run/openvpn-udp-stage.socket unix
   management-client-group vpnmgmt

TODO
----

- use mozlibldap for the duo script
