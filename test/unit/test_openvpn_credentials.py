# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" openvpnredentials class unit test script """

import unittest
import os
import test.context  # pylint: disable=unused-import
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials


class CredentialsTestMixin(object):
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

    def setUp(self):  # pylint: disable=invalid-name
        """ Preparing test rig """
        self.realish_user = self.__class__.REALISH_USER
        self.realish_passcode = self.__class__.REALISH_PASSCODE
        self.bad_passcode = self.__class__.BAD_PASSCODE
        self.library = OpenVPNCredentials()

    @staticmethod
    def tearDown():  # pylint: disable=invalid-name
        """ Clear the env so we don't impact other tests """
        for varname in ['common_name', 'password', 'username', 'untrusted_ip']:
            if varname in os.environ:
                del os.environ[varname]


class X1IsAPasscode(CredentialsTestMixin, unittest.TestCase):
    """ Test the utility function is_a_passcode """

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


class X2LoadEnvAwful(CredentialsTestMixin, unittest.TestCase):
    """
        Testing get_variables_from_environment.  This function does almost no
        checks of the QUALITY of the data, just the existence.  Thus this test
        class can do tests concerned with "a string-IN became a string-OUT
        in the right place" only.
    """
    def test_getenv_garbage(self):
        """ without env vars at all, we fail noisily """
        with self.assertRaises(ValueError):
            self.library.load_variables_from_environment()
        self.assertFalse(self.library.is_valid(),
                         'object.is_valid must be false if load fails')

    def test_getenv_noinputs(self):
        """ common_name-only gives appropriate blanks """
        # Given a common_name helps, but when there's no user/pass
        # we can't do much.  Make sure None's are gone.
        os.environ['common_name'] = self.realish_user
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, '')
        self.assertEqual(self.library.passcode, None)
        self.assertEqual(self.library.factor, None)


class X4LoadEnvNormal(CredentialsTestMixin, unittest.TestCase):
    """
        This class exercises a call into load_variables_from_environment
        'the normal way' - no arguments.  This is not a complete test,
        intentionally.  If this works, we know we haven't broken the
        chief entry point of the function and integration should work.
        The classes beyond this will unit test input scenarios.
    """
    def test_loadenv_soup2nuts(self):
        """ test load_variables_from_environment as if production """
        # Invoke load_variables_from_environment as a normal non-args call
        # This tests that we can run through the normal codepath.
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = self.realish_user
        os.environ['password'] = self.realish_passcode
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')


# Below here, we bypass the environmental stuff and pass arguments,
# as it makes for easier-to-test cases.

# Here it starts getting complex as we try to handle all the test cases
#
# +-----------------------+------+--------------------+-----------------+
# | vPass         User>   |  ''  | DUO_RESERVED_WORDS | anything else   |
# +-----------------------+------+--------------------+-----------------+
# |  ''                   |  00  |         10         |       20        |
# | DUO_RESERVED_WORDS    |  01  |         11         |       21        |
# | a_passcode            |  02  |         12         |       22        |
# | 'passcode:'a_passcode |  03  |         13         |       23        |
# | 'passcode:junk'       |  04  |         14         |       24        |
# | a_password:a_passcode |  05  |         15         |       25        |
# | some:password         |  06  |         16         |       26        |
# | some_password         |  07  |         17         |       27        |
# +-----------------------+------+--------------------+-----------------+


class X5LoadEnvNullUser(CredentialsTestMixin, unittest.TestCase):
    """ A suite of tests where we have no username provided """
    def test_loadvar_00(self):
        """ user '' pass '' """
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = ''
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, '')
        self.assertEqual(self.library.passcode, None)
        self.assertEqual(self.library.factor, None)

    def test_loadvar_01(self):
        """ user '' pass DUO_RESERVED_WORDS """
        for wordp in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = ''
            os.environ['password'] = wordp
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, None)
            self.assertEqual(self.library.passcode, None)
            self.assertEqual(self.library.factor, wordp)

    def test_loadvar_02(self):
        """ user '' pass a_passcode """
        _pass = self.realish_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_03(self):
        """ user '' pass passcode:a_passcode """
        _pass = 'passcode:'+self.realish_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_04(self):
        """ user '' pass passcode:not_a_passcode """
        _pass = 'passcode:'+self.bad_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        # Note that this is deliberate:
        self.assertEqual(self.library.passcode, self.bad_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_05(self):
        """ user '' pass a_password:a_passcode """
        _rawpass = 'somepass'
        _pass = _rawpass+':'+self.realish_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, _rawpass)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_06(self):
        """ user '' pass a_pa:ss:wo:rd """
        _pass = 'some:password'
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, _pass)
        self.assertEqual(self.library.passcode, None)
        self.assertEqual(self.library.factor, None)

    def test_loadvar_07(self):
        """ user '' pass a_password """
        _pass = 'some_password'
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = ''
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, _pass)
        self.assertEqual(self.library.passcode, None)
        self.assertEqual(self.library.factor, None)

    ############################################################################3


class X6LoadEnvDuoUser(CredentialsTestMixin, unittest.TestCase):
    """ A suite of tests where we have a DUO_RESERVED_WORDS username """
    def test_loadvar_10(self):
        """ user DUO_RESERVED_WORDS pass '' """
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = ''
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, None)
            self.assertEqual(self.library.passcode, None)
            self.assertEqual(self.library.factor, wordu)

    def test_loadvar_11(self):
        """ user DUO_RESERVED_WORDS pass DUO_RESERVED_WORDS """
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            for wordp in list(self.library.DUO_RESERVED_WORDS):
                os.environ['common_name'] = self.realish_user
                os.environ['username'] = wordu
                os.environ['password'] = wordp
                self.library.load_variables_from_environment()
                self.assertTrue(self.library.is_valid())
                self.assertEqual(self.library.username, self.realish_user)
                self.assertEqual(self.library.password, None)
                self.assertEqual(self.library.passcode, None)
                self.assertEqual(self.library.factor, wordp)

    def test_loadvar_12(self):
        """ user DUO_RESERVED_WORDS pass a_passcode """
        _pass = self.realish_passcode
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = _pass
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, None)
            self.assertEqual(self.library.passcode, self.realish_passcode)
            self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_13(self):
        """ user DUO_RESERVED_WORDS pass passcode:a_passcode """
        _pass = 'passcode:'+self.realish_passcode
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = _pass
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, None)
            self.assertEqual(self.library.passcode, self.realish_passcode)
            self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_14(self):
        """ user DUO_RESERVED_WORDS pass passcode:not_a_passcode """
        _pass = 'passcode:'+self.bad_passcode
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = _pass
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, None)
            # Note that this is deliberate:
            self.assertEqual(self.library.passcode, self.bad_passcode)
            self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_15(self):
        """ user DUO_RESERVED_WORDS pass a_password:a_passcode """
        _rawpass = 'somepass'
        _pass = _rawpass+':'+self.realish_passcode
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = _pass
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, _rawpass)
            self.assertEqual(self.library.passcode, self.realish_passcode)
            self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_16(self):
        """ user DUO_RESERVED_WORDS pass a_pa:ss:wo:rd """
        _pass = 'some:password'
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = _pass
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, _pass)
            self.assertEqual(self.library.passcode, None)
            self.assertEqual(self.library.factor, None)

    def test_loadvar_17(self):
        """ user DUO_RESERVED_WORDS pass a_password """
        _pass = 'some_password'
        for wordu in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = wordu
            os.environ['password'] = _pass
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, _pass)
            self.assertEqual(self.library.passcode, None)
            self.assertEqual(self.library.factor, None)

    ############################################################################3


class X7LoadEnvSomewordUser(CredentialsTestMixin, unittest.TestCase):
    """ A suite of tests where we have some misc username """
    def test_loadvar_20(self):
        """ user someuser pass '' """
        # This case is somewhat of a don't-care, and you may change this
        # test case in the future.  What this simulates is, someone typed
        # in SOMETHING (maybe their username?) in the user field, but didn't
        # put in the password field (no passcode, or 'push').  Likely that
        # means this is either a typo ('puush' or '12345') or a premature
        # click on submit.
        #
        # Now, what we do with this is kinda irrelevant, whether we raise
        # or have a non-factor result.  So:
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = ''
        try:
            self.library.load_variables_from_environment()
        except ValueError:  # pragma: no cover
            # If we error'ed, that's fine.
            self.assertFalse(self.library.is_valid(),
                             'object.is_valid must be false if load fails')
        else:  # pragma: no cover
            # If we loaded, we need to check this out:
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, '')
            self.assertEqual(self.library.passcode, None)
            self.assertEqual(self.library.factor, None)

    def test_loadvar_21(self):
        """ user someuser pass DUO_RESERVED_WORDS """
        for wordp in list(self.library.DUO_RESERVED_WORDS):
            os.environ['common_name'] = self.realish_user
            os.environ['username'] = 'someuser'
            os.environ['password'] = wordp
            self.library.load_variables_from_environment()
            self.assertTrue(self.library.is_valid())
            self.assertEqual(self.library.username, self.realish_user)
            self.assertEqual(self.library.password, None)
            self.assertEqual(self.library.passcode, None)
            self.assertEqual(self.library.factor, wordp)

    def test_loadvar_22(self):
        """ user someuser pass a_passcode """
        _pass = self.realish_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_23(self):
        """ user someuser pass passcode:a_passcode """
        _pass = 'passcode:'+self.realish_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_24(self):
        """ user someuser pass passcode:not_a_passcode """
        _pass = 'passcode:'+self.bad_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, None)
        # Note that this is deliberate:
        self.assertEqual(self.library.passcode, self.bad_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_25(self):
        """ user someuser pass a_password:a_passcode """
        _rawpass = 'somepass'
        _pass = _rawpass+':'+self.realish_passcode
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, _rawpass)
        self.assertEqual(self.library.passcode, self.realish_passcode)
        self.assertEqual(self.library.factor, 'passcode')

    def test_loadvar_26(self):
        """ user someuser pass a_pa:ss:wo:rd """
        _pass = 'some:password'
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, _pass)
        self.assertEqual(self.library.passcode, None)
        self.assertEqual(self.library.factor, None)

    def test_loadvar_27(self):
        """ user someuser pass a_password """
        _pass = 'some_password'
        os.environ['common_name'] = self.realish_user
        os.environ['username'] = 'someuser'
        os.environ['password'] = _pass
        self.library.load_variables_from_environment()
        self.assertTrue(self.library.is_valid())
        self.assertEqual(self.library.username, self.realish_user)
        self.assertEqual(self.library.password, _pass)
        self.assertEqual(self.library.passcode, None)
        self.assertEqual(self.library.factor, None)
