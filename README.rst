===========
Duo_openvpn
===========

Mozilla's take at duo_openvpn support.
Duo's own duo_openvpn appears to be aging off.  We rewrote it to use duo_client_python, as well as logging for operational security needs.

Git submodules
--------------

In order to checkout all the modules necessary for this to build, run

.. code::

	git clone --recursive git@github.com:mozilla-it/duo_openvpn.git
	# Or, if already checked out:
	git submodule update --init --recursive

Features
--------

- Simple.  Sort of.
- Fail open (optional).
- OTP and Push (use push as password for push, passcode:123456 as password for OTP, where 123456 is your OTP).
- Optional-username hack, in case you use emails as certificate CN but only the first part of the email as login.
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
