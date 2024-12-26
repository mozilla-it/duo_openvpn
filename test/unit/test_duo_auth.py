# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" duo_auth class unit test without touching Duo itself """

import unittest
import os
import socket
import configparser
import http.client
import test.context  # pylint: disable=unused-import
import mock
import duo_client
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
from duo_openvpn_mozilla import DuoOpenVPN


class TestDuoAPIAuthUnit(unittest.TestCase):
    """
        These are intended to exercise internal functions of the library's
        DuoAPIAuth class without going out to Duo.
    """

    testing_conffile = '/tmp/TestDuoAPIAuthUnit.txt'  # nosec hardcoded_tmp_directory

    def setUp(self):
        """ Preparing test rig """
        # To get a decent test, we're going to need items from the config
        # file in order to test.
        config = configparser.ConfigParser()
        config.add_section('duo-credentials')
        config.set('duo-credentials', 'IKEY', 'DI9QQ99X9MK4H99RJ9FF')
        config.set('duo-credentials', 'SKEY', '2md9rw5xeyxt8c648dgkmdrg3zpvnhj5b596mgku')
        config.set('duo-credentials', 'HOST', 'api-9f134ff9.duosekurity.com')
        with open(self.testing_conffile, 'w', encoding='utf-8') as configfile:
            config.write(configfile)

        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['duo_openvpn.conf',
                                    '/usr/local/etc/duo_openvpn.conf',
                                    '/etc/openvpn/duo_openvpn.conf',
                                    '/etc/duo_openvpn.conf',
                                    self.testing_conffile]):
            self.main_object = DuoOpenVPN()
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        user_creds = {}
        for varname in OpenVPNCredentials.DUO_RESERVED_WORDS:
            os.environ['password'] = varname
            res = OpenVPNCredentials()
            res.load_variables_from_environment()
            user_creds[varname] = res
        self.user_data = user_creds
        #
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['duo_openvpn.conf',
                                    '/usr/local/etc/duo_openvpn.conf',
                                    '/etc/openvpn/duo_openvpn.conf',
                                    '/etc/duo_openvpn.conf',
                                    self.testing_conffile]):
            self.library = DuoAPIAuth(**self.main_object.duo_client_args)

    def tearDown(self):
        """ Clear the env so we don't impact other tests """
        for varname in ['common_name', 'password', 'username', 'untrusted_ip']:
            if varname in os.environ:
                del os.environ[varname]
        try:
            os.unlink(self.testing_conffile)
        except OSError:  # pragma: no cover
            # ... else, there was nothing there (likely) ...
            if os.path.exists(self.testing_conffile):
                # ... but if there is, we couldn't delete it, so complain.
                raise

    def test_init(self):
        """ Verify init does the right thing """
        self.assertIsInstance(self.library, duo_client.Auth,
                              'our DuoAPIAuth must be a descendant '
                              'of duo_client.Auth')
        self.assertIsInstance(self.library.hostname, str,
                              'hostname must be set and a string')
        self.assertIsInstance(self.library._fail_open, bool,
                              '_fail_open must return a bool')
        self.assertIsNone(self.library.user_config,
                          'user_config must be empty on a plain init')
        self.assertIsNone(self.library.log_func,
                          'log_func must default to None')

    def test_fail_open_00(self):
        """ _fail_open performs as expected """
        res = self.library._fail_open
        self.assertIsInstance(res, bool, '_fail_open must return a bool')
        self.assertFalse(res, '_fail_open defaults to False')

    def test_fail_open_01(self):
        """ _fail_open performs as expected on a True """
        tmplibrary = DuoAPIAuth(fail_open=True,
                                **self.main_object.duo_client_args)
        res = tmplibrary._fail_open
        self.assertIsInstance(res, bool, '_fail_open must return a bool')
        self.assertTrue(res, '_fail_open must return an expected True')

    def test_fail_open_02(self):
        """ _fail_open performs as expected on a False """
        tmplibrary = DuoAPIAuth(fail_open=False,
                                **self.main_object.duo_client_args)
        res = tmplibrary._fail_open
        self.assertIsInstance(res, bool, '_fail_open must return a bool')
        self.assertFalse(res, '_fail_open must return an expected False')

    def test_load_user_to_verify_00(self):
        """ load_user_to_verify can fail for garbage """
        res = self.library.load_user_to_verify({})
        self.assertFalse(res, 'load_user_to_verify must be False '
                         'for junk input')

    def test_load_user_to_verify_01(self):
        """ load_user_to_verify can fail for a bad username """
        setattr(self.user_data['push'], 'username', 0)
        res = self.library.load_user_to_verify(self.user_data['push'])
        self.assertFalse(res, 'load_user_to_verify must be False '
                         'for a bad username')

    def test_load_user_to_verify_02(self):
        """ load_user_to_verify can fail for a bad factor """
        setattr(self.user_data['push'], 'factor', 0)
        res = self.library.load_user_to_verify(self.user_data['push'])
        self.assertFalse(res, 'load_user_to_verify must be False '
                         'for a bad factor')

    def test_load_user_to_verify_03(self):
        """ load_user_to_verify can succeed and return True """
        res = self.library.load_user_to_verify(self.user_data['push'])
        self.assertTrue(res, 'load_user_to_verify must be True')

    def test_log(self):
        """ Test the weird logging function """
        with mock.patch.object(self.library, 'log_func') as mock_dummy:
            self.library.log('foo', bar='quux')
        mock_dummy.assert_called_once_with('foo', bar='quux')

    def test_10_preflight(self):
        """ Test various levels of preflight checks """
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'ping', side_effect=socket.error):
                res = self.library._preflight()
            self.assertFalse(res, "Broken ping must return False")
            # Check the call_args - [1] is the kwargs.
            #self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            #self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'ping', return_value=None):
                with mock.patch.object(self.library, 'check', side_effect=socket.error):
                    res = self.library._preflight()
            self.assertFalse(res, "Broken check must return False")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'ping', return_value=None):
                with mock.patch.object(self.library, 'check', side_effect=RuntimeError):
                    res = self.library._preflight()
            self.assertFalse(res, "Broken check must return False")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'ping', return_value=None):
            with mock.patch.object(self.library, 'check', return_value=None):
                res = self.library._preflight()
            self.assertTrue(res, "Good preflight check must return True")

    def test_20_preauth(self):
        """ Test various levels of preauth checks """
        # a _preauth without users configured must fail hard:
        with self.assertRaises(Exception):
            self.library._preauth()

        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'preauth', side_effect=socket.error):
                res = self.library._preauth()
            self.assertFalse(res, "Broken check must return False")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'preauth', side_effect=RuntimeError):
                res = self.library._preauth()
            self.assertFalse(res, "Broken check must return False")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'preauth',
                                   side_effect=http.client.BadStatusLine('')):
                res = self.library._preauth()
            self.assertFalse(res, "Broken check must return False")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        upstream_return = ['some', 14, 'thing']
        with mock.patch.object(self.library, 'preauth', return_value=upstream_return):
            res = self.library._preauth()
        self.assertEqual(res, upstream_return, "Good preauth returns whatever upstream sent")

    def test_30_auth_fails(self):
        """ Test various failure levels of auth checks """
        # a _auth without users configured must fail hard:
        with self.assertRaises(Exception):
            self.library._auth()

        # SMS can't auth:
        with mock.patch.object(self.library, 'log') as mock_log:
            self.library.user_config = self.user_data['sms']
            res = self.library._auth()
            self.assertIsNone(res, "sms _auth must return None")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        # garbage factors can't auth:
        with mock.patch.object(self.library, 'log') as mock_log:
            self.library.user_config = self.user_data['push']
            self.library.user_config.factor = 'nonsense'
            res = self.library._auth()
            self.assertIsNone(res, "nonsense factor _auth must return None")
            # Check the call_args - [1] is the kwargs.
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_32_auth_phone(self):
        """ Test phone on auth checks. """
        # Remember that 'phone' is a garbage code path.  If you break here,
        # feel free to attack this problem some other way.
        self.library.user_config = self.user_data['phone']
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=socket.error):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=RuntimeError):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        upstream_return = ['some', 32, 'thing']
        with mock.patch.object(self.library, 'auth', return_value=upstream_return) as mock_auth:
            res = self.library._auth()
        self.assertEqual(res, upstream_return, "Good auth returns whatever upstream sent")
        self.assertEqual(mock_auth.call_args[1]['device'], 'auto')

    def test_33_auth_auto(self):
        """ Test auto on auth checks. """
        # Remember that 'auto' is a garbage code path.  If you break here,
        # feel free to attack this problem some other way.
        self.library.user_config = self.user_data['auto']
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=socket.error):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=RuntimeError):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        upstream_return = ['some', 33, 'thing']
        with mock.patch.object(self.library, 'auth', return_value=upstream_return) as mock_auth:
            res = self.library._auth()
        self.assertEqual(res, upstream_return, "Good auth returns whatever upstream sent")
        self.assertEqual(mock_auth.call_args[1]['device'], 'auto')

    def test_34_auth_passcode(self):
        """ Test passcode on auth checks. """
        os.environ['password'] = '123456'  # nosec hardcoded_password_string
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.library.user_config = creds
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=socket.error):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=RuntimeError):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        upstream_return = ['some', 34, 'thing']
        with mock.patch.object(self.library, 'auth', return_value=upstream_return) as mock_auth:
            res = self.library._auth()
        self.assertEqual(res, upstream_return, "Good auth returns whatever upstream sent")
        self.assertEqual(mock_auth.call_args[1]['passcode'], self.library.user_config.passcode)

    def test_35_auth_push(self):
        """ Test push on auth checks. """
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=socket.error):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, 'auth', side_effect=RuntimeError):
                res = self.library._auth()
            self.assertIsNone(res, "Failed _auth must return None")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        upstream_return = ['some', 35, 'thing']
        with mock.patch.object(self.library, 'auth', return_value=upstream_return) as mock_auth:
            res = self.library._auth()
        self.assertEqual(res, upstream_return, "Good auth returns whatever upstream sent")
        self.assertEqual(mock_auth.call_args[1]['device'], 'auto')

    def test_40_do_mfa(self):
        """ Unit test for _do_mfa_for_user """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_auth', return_value=None):
            res = self.library._do_mfa_for_user()
        self.assertFalse(res, "Failed _auth must cause _do_mfa_for_user to be False")

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, '_auth', return_value='weirdness'):
                res = self.library._do_mfa_for_user()
            self.assertFalse(res, "Garbage _auth must cause _do_mfa_for_user to be False")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, '_auth', return_value={'result': 'allow'}):
                res = self.library._do_mfa_for_user()
            self.assertTrue(res, "Allowed _auth must cause _do_mfa_for_user to be True")
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'true')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, '_auth', return_value={'result': 'deny',
                                                                        'status_msg': 'Nope'}):
                res = self.library._do_mfa_for_user()
            self.assertFalse(res, "Denied _auth must cause _do_mfa_for_user to be False")
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')


    def test_50_main_auth_awful1(self):
        """ Test main_auth that fail preflight """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, '_preflight', return_value=False):
                self.library._fail_open = True
                #with mock.patch.object(self.library, '_fail_open', return_value=True):
                res = self.library.main_auth()
        self.assertTrue(res, "main_auth follows fail_open when preflight fails")
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'true')

        with mock.patch.object(self.library, 'log') as mock_log:
            with mock.patch.object(self.library, '_preflight', return_value=False):
                self.library._fail_open = False
                res = self.library.main_auth()
        self.assertFalse(res, "main_auth follows fail_open when preflight fails")
        mock_log.assert_not_called()

    def test_51_main_auth_awful2(self):
        """ Test main_auth that fail preauth """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_preflight', return_value=True):
            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth', return_value=None):
                    res = self.library.main_auth()
            self.assertFalse(res, "main_auth should fail when preauth fails")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth', return_value='junk'):
                    res = self.library.main_auth()
            self.assertFalse(res, "main_auth should fail when preauth has an API failure")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_52_main_auth_allow(self):
        """ Test main_auth when it gets an 'allow' response """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_preflight', return_value=True):
            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth', return_value={'result': 'allow'}):
                    res = self.library.main_auth()
            self.assertTrue(res, "main_auth should allow when preauth gets an allow")
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'true')

    def test_53_main_auth_enroll(self):
        """ Test main_auth when it gets an 'enroll' response """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_preflight', return_value=True):
            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth', return_value={'result': 'enroll'}):
                    res = self.library.main_auth()
            self.assertFalse(res, "main_auth should deny when preauth gets an enroll")
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_54_main_auth_deny(self):
        """ Test main_auth when it gets a 'deny' response """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_preflight', return_value=True):
            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth', return_value={'result': 'deny'}):
                    res = self.library.main_auth()
            self.assertFalse(res, "main_auth should deny when preauth gets a deny")
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_55_main_auth_auth(self):
        """ Test main_auth when it gets an 'auth' response """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_preflight', return_value=True):
            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth', return_value={'result': 'auth'}):
                    upstream_return = ['some', 55, 'thing']
                    with mock.patch.object(self.library, '_do_mfa_for_user',
                                           return_value=upstream_return):
                        res = self.library.main_auth()
            self.assertEqual(res, upstream_return, "main_auth should deny when preauth gets a deny")
            mock_log.assert_not_called()

    def test_59_main_auth_nonsense(self):
        """ Test main_auth when it gets an unexpected response """
        # It doesn't particularly matter what kind of user we have, so picked 'push'  *shrug*
        self.library.user_config = self.user_data['push']
        with mock.patch.object(self.library, '_preflight', return_value=True):
            with mock.patch.object(self.library, 'log') as mock_log:
                with mock.patch.object(self.library, '_preauth',
                                       return_value={'result': 'never_seen_this'}):
                    res = self.library.main_auth()
            self.assertFalse(res, "main_auth should deny when preauth gets something unexpected")
            self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
            self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')
