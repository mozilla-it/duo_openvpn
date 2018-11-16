# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" duo_openvpn_mozilla class unit test script """
# This test file is all about calling protected methods on the
# library files, so, we tell pylint that we're cool with it:
# pylint: disable=protected-access

import unittest
import os
import sys
sys.path.insert(1, 'duo_client')
sys.path.insert(1, 'iamvpnlibrary')
sys.path.insert(1, 'mozdef_client')
sys.path.insert(1, 'mozdef_client_config')
from duo_openvpn_mozilla import DuoOpenVPN  # pylint: disable=wrong-import-position
sys.dont_write_bytecode = True


class TestDuoOpenVPN(unittest.TestCase):
    """
        These are intended to exercise internal functions of the library's
        DuoOpenVPN class.
    """

    def setUp(self):
        """ Preparing test rig """
        # Our test cases depend on the setup of an object that reads
        # in the environment at the time we create an object of our
        # test class.  As such, we don't have a good setup here.
        # Each test will have to do a lot of situational setup.
        # That said, we make a garbage object just to get our library read:
        self.main_object = DuoOpenVPN()
        self.normal_user = self.main_object.configfile.get(
            'testing', 'normal_user')
        if self.main_object.configfile.has_option('testing',
                                                  'deep_testing_mainauth'):
            self.deep_test_main = self.main_object.configfile.getboolean(
                'testing', 'deep_testing_mainauth')
        else:
            self.deep_test_main = False
        #
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'

    def tearDown(self):
        """ Clear the env so we don't impact other tests """
        for varname in ['common_name', 'password', 'username', 'untrusted_ip']:
            if varname in os.environ:
                del os.environ[varname]

    def test_init(self):
        """ Verify init does the right thing """
        self.assertIsNotNone(self.main_object.configfile,
                             'DuoOpenVPN must have a valid configfile')
        self.assertIsInstance(self.main_object.failopen, bool,
                              '_fail_open must return a bool')
        self.assertIsInstance(self.main_object.duo_client_args, dict,
                              'duo_client_args must be a dict')
        self.assertIsInstance(self.main_object.log_to_stdout, bool,
                              'log_to_stdout must be a bool')

    def test_bogus_user(self):
        """ A bogus user is denied """
        os.environ['common_name'] = 'user-who-does-not-exist'
        os.environ['password'] = 'push'
        library = DuoOpenVPN()
        library.log_to_stdout = False
        res = library.main_authentication()
        self.assertFalse(res, 'invalid users must be denied')

    def test_1fa_user_bad_pw(self):
        """ A 1FA user with a bad password fails """
        if not self.main_object.configfile.has_section('testing'):
            return self.skipTest('No testing section defined')
        if not self.main_object.configfile.has_option('testing',
                                                      'one_fa_user'):
            return self.skipTest('No testing/one_fa_user defined')
        one_fa_user = self.main_object.configfile.get('testing',
                                                      'one_fa_user')
        os.environ['common_name'] = one_fa_user
        os.environ['password'] = 'a-bad-password'
        library = DuoOpenVPN()
        library.log_to_stdout = False
        res = library.main_authentication()
        self.assertFalse(res, '1fa user with bad password must be denied')

    def test_1fa_user_good_pw(self):
        """ A 1FA user with a good password works """
        if not self.main_object.configfile.has_section('testing'):
            return self.skipTest('No testing section defined')
        if not self.main_object.configfile.has_option('testing',
                                                      'one_fa_user'):
            return self.skipTest('No testing/one_fa_user defined')
        one_fa_user = self.main_object.configfile.get('testing',
                                                      'one_fa_user')
        if not self.main_object.configfile.has_option('testing',
                                                      'one_fa_pass'):
            return self.skipTest('No testing/one_fa_pass defined')
        one_fa_pass = self.main_object.configfile.get('testing',
                                                      'one_fa_pass')
        os.environ['common_name'] = one_fa_user
        os.environ['password'] = one_fa_pass
        library = DuoOpenVPN()
        library.log_to_stdout = False
        res = library.main_authentication()
        self.assertTrue(res, '1fa user with good password gets accepted')

    def test_2fa_user_bad(self):
        """ A 2FA user with a bad push fails  PLEASE DENY """
        if not self.deep_test_main:
            return self.skipTest('because of .deep_testing preference')
        os.environ['common_name'] = self.normal_user
        os.environ['password'] = 'push'
        library = DuoOpenVPN()
        library.log_to_stdout = False
        res = library.main_authentication()
        self.assertFalse(res, '2fa user with a deny must be False')

    def test_2fa_user_good(self):
        """ A 2FA user with a bad push fails  PLEASE ALLOW """
        if not self.deep_test_main:
            return self.skipTest('because of .deep_testing preference')
        os.environ['common_name'] = self.normal_user
        os.environ['password'] = 'push'
        library = DuoOpenVPN()
        library.log_to_stdout = False
        res = library.main_authentication()
        self.assertTrue(res, '2fa user with an allow must be True')

    def test_log_good(self):
        """ Test sending a log message to mozdef - all good """
        # There is no raise or return.  We're just poking at
        # the function and making sure it doesn't raise.
        self.main_object.log_to_stdout = False
        self.main_object.log(summary='test message',
                             severity='DEBUG',
                             details={'test': 1})

    def test_log_bad1(self):
        """ Test sending a log message to mozdef - bad severity """
        # There is no raise or return.  We're just poking at
        # the function and making sure it doesn't raise.
        # This has a garbage severity, function should correct it.
        self.main_object.log_to_stdout = False
        self.main_object.log(summary='test message',
                             severity='blerp',
                             details={'test': 1})
