===========
Duo_openvpn
===========

Our own take at duo_openvpn support.
Not very happy with the provided duo_openvpn support, we rewrote it to use duo_client_python which is much nicer.

Features
--------

- Simple. Sort of.
- Auth caching per login+ip address.
- Fail open (optional).
- OTP and Push (use push as password for push, passcode:123456 as password for OTP, where 123456 is your OTP).
- CEF support.
- Optional username hack, in case you use emails as certificate CN but only the first part of the email as login.
- Supports logging with LDAP with or instead-of Duo.

TODO
----

- Support for control file. We don't use it, but some may. Not really hard to add, tho.
- Add direct LDAP lookup support for groups.
