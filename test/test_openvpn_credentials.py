#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" openvpnredentials class unit test script """
# This test file is all about calling protected methods on the
# library files, so, we tell pylint that we're cool with it:
# pylint: disable=protected-access

import unittest
import os
import sys
sys.path.insert(1, 'duo_openvpn_mozilla')
from openvpn_credentials import OpenVPNCredentials  # pylint: disable=wrong-import-position
sys.dont_write_bytecode = True


class TestOpenVPNCredentials(unittest.TestCase):  # pylint:  disable=too-many-public-methods
    """
        These are intended to exercise internal functions of the library's
        OpenVPNCredentials class.
        We don't have to provide any REAL users for this test piece, since
        this class is all about handling environmental variable inputs
        coming from openvpn, so we just make things up.
    """
    REALISH_USER = 'foo@bar.org'
    REALISH_PASSCODE = '123456'
    BAD_PASSCODE = '1234'

    def setUp(self):
        """ Preparing test rig """
        self.realish_user = self.__class__.REALISH_USER
        self.realish_passcode = self.__class__.REALISH_PASSCODE
        self.bad_passcode = self.__class__.BAD_PASSCODE
        self.library = OpenVPNCredentials()

    def tearDown(self):
        """ Clear the env so we don't impact other tests """
        for varname in ['common_name', 'password', 'username', 'untrusted_ip']:
            if varname in os.environ:
                del os.environ[varname]

    def test_openvpnredentials_01(self):
        """ without env vars at all, we fail noisily """
        with self.assertRaises(ValueError):
            self.library.load_variables_from_environment()

    def test_openvpnredentials_02(self):
        """ common_name-only fails """
        # Given a common_name helps, but when there's no user/pass,
        # we still need to die.
        os.environ['common_name'] = self.realish_user
        with self.assertRaises(ValueError):
            self.library.load_variables_from_environment()
        self.assertFalse(self.library.is_valid(),
                         'object.is_valid must be false if load fails')

    def test_openvpnredentials_13(self):
        """ common_name and good passcode works """
        # A good use: someone passed in user+passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = self.realish_passcode
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEquals(self.library.username, self.realish_user)
        self.assertEquals(self.library.password, None)
        self.assertEquals(self.library.passcode, self.realish_passcode)
        self.assertEquals(self.library.factor, 'passcode')

    def test_openvpnredentials_14(self):
        """ common_name, username, and no passcode fails """
        # Here someone comes in without a passcode or password.
        # Die peacefully.
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = ''
        with self.assertRaises(ValueError):
            self.library.load_variables_from_environment()
        self.assertFalse(self.library.is_valid(),
                         'object.is_valid must be false if load fails')

    def test_openvpnredentials_15(self):
        """ common_name, bad passcode as a username fails """
        # Here someone puts in a junk passcode in the user field
        # Die peacefully.
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.bad_passcode
        os.environ['password'] = ''
        with self.assertRaises(ValueError):
            self.library.load_variables_from_environment()
        self.assertFalse(self.library.is_valid(),
                         'object.is_valid must be false if load fails')

    def test_openvpnredentials_16(self):
        """ common_name, good passcode as a username works """
        # Here someone puts in a real passcode in the user field
        # We accept this, oddly, because it's a situation where
        # some clients will send passcodes this way, like, if you
        # have a totp key that shoves it in the first field.
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_passcode
        os.environ['password'] = ''
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEquals(self.library.username, self.realish_user)
        self.assertEquals(self.library.password, None)
        self.assertEquals(self.library.passcode, self.realish_passcode)
        self.assertEquals(self.library.factor, 'passcode')

    def test_openvpnredentials_17(self):
        """ the duo reserved words as passwords """
        # Test the Duo reserved words, that someone who uses them
        # as a password, gets in.
        # This is THE main use case, where someone says 'push'.
        for method in ['auto', 'push', 'sms', 'phone']:
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = self.realish_user
            os.environ['password'] = method
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEquals(self.library.username, self.realish_user)
            self.assertEquals(self.library.password, None)
            self.assertEquals(self.library.passcode, None)
            self.assertEquals(self.library.factor, method)

    def test_openvpnredentials_18(self):
        """ the duo reserved words as usernames"""
        # Test the Duo reserved words, that someone who uses them
        # as a password, gets in.
        # This is THE main use case, where someone says 'push'.
        for method in ['auto', 'push', 'sms', 'phone']:
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = method
            os.environ['password'] = ''
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEquals(self.library.username, self.realish_user)
            self.assertEquals(self.library.password, None)
            self.assertEquals(self.library.passcode, None)
            self.assertEquals(self.library.factor, method)

    def test_openvpnredentials_28(self):
        """ common_name, username, and a plaintext password gets no factor """
        # Someone who uses a login+conventional password,
        # should not have a factor
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = 'hunter2'
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEquals(self.library.username, self.realish_user)
        self.assertEquals(self.library.password, 'hunter2')
        self.assertEquals(self.library.passcode, None)
        self.assertEquals(self.library.factor, None)

    def test_openvpnredentials_29(self):
        """ common_name, username, and passcode:code works """
        # A password of the literal string 'passcode' colon somecode
        # is good.  We deliberately test a complex passcode here.
        _crazy_passcode = 'abcd1234qwerty'
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = 'passcode:'+_crazy_passcode
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEquals(self.library.username, self.realish_user)
        self.assertEquals(self.library.password, None)
        self.assertEquals(self.library.passcode, _crazy_passcode)
        self.assertEquals(self.library.factor, 'passcode')

    def test_openvpnredentials_30(self):
        """ common_name, username, and passwd:code works """
        # A password of somepassword colon somecode
        # is good.
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = 'hunter2:'+self.realish_passcode
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEquals(self.library.username, self.realish_user)
        self.assertEquals(self.library.password, 'hunter2')
        self.assertEquals(self.library.passcode, self.realish_passcode)
        self.assertEquals(self.library.factor, 'passcode')

    def test_openvpnredentials_31(self):
        """ common_name, username, and pass:word is only a password """
        # A password of somepassword colon somecode
        # is good.
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = 'pa:ss:wo:rd'
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEquals(self.library.username, self.realish_user)
        self.assertEquals(self.library.password, 'pa:ss:wo:rd')
        self.assertEquals(self.library.passcode, None)
        self.assertEquals(self.library.factor, None)

    def test_passcodes_04(self):
        """ passcode:1234 is not valid """
        self.assertFalse(self.library.is_a_passcode('1234'))

    def test_passcodes_05(self):
        """ passcode:12345 is not valid """
        self.assertFalse(self.library.is_a_passcode('12345'))

    def test_passcodes_06(self):
        """ passcode:123456 is valid """
        self.assertTrue(self.library.is_a_passcode('123456'))

    def test_passcodes_07(self):
        """ passcode:1234567 is valid """
        self.assertTrue(self.library.is_a_passcode('1234567'))

    def test_passcodes_08(self):
        """ passcode:12345678 is valid """
        self.assertTrue(self.library.is_a_passcode('12345678'))

    def test_passcodes_09(self):
        """ passcode:123456789 is not valid """
        self.assertFalse(self.library.is_a_passcode('123456789'))

    def test_passcodes_10(self):
        """ passcode:-123456 is not valid """
        self.assertFalse(self.library.is_a_passcode('-123456'))

    def test_passcodes_11(self):
        """ passcode:123A56 is not valid """
        self.assertFalse(self.library.is_a_passcode('123A56'))
