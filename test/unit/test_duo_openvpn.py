# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" duo_auth class unit test without touching Duo itself """

import unittest
import os
import sys
import test.context  # pylint: disable=unused-import
import mock
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
from duo_openvpn_mozilla import DuoOpenVPN
try:
    import configparser
except ImportError:  # pragma: no cover
    from six.moves import configparser
if sys.version_info.major >= 3:
    from io import StringIO  # pragma: no cover
else:
    from io import BytesIO as StringIO  # pragma: no cover


class TestDuoOpenVPNUnit(unittest.TestCase):
    """
        These are intended to exercise internal functions of the library's
        DuoOpenVPN class without going out to Duo.
    """

    testing_conffile = '/tmp/TestDuoOpenVPNUnit.txt'

    def setUp(self):
        """ Preparing test rig """
        # Our test cases depend on the setup of an object that reads
        # in the environment at the time we create an object of our
        # test class.  As such, we don't have a good setup here.
        # Each test will have to do a lot of situational setup.
        # That said, we make a garbage object just to get our library read:

        config = configparser.ConfigParser()
        config.add_section('duo-credentials')
        config.set('duo-credentials', 'IKEY', 'DI9QQ99X9MK4H99RJ9FF')
        config.set('duo-credentials', 'SKEY', '2md9rw5xeyxt8c648dgkmdrg3zpvnhj5b596mgku')
        config.set('duo-credentials', 'HOST', 'api-9f134ff9.duosekurity.com')
        with open(self.testing_conffile, 'w') as configfile:
            config.write(configfile)
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['duo_openvpn.conf',
                                    '/usr/local/etc/duo_openvpn.conf',
                                    '/etc/openvpn/duo_openvpn.conf',
                                    '/etc/duo_openvpn.conf',
                                    self.testing_conffile]):
            self.library = DuoOpenVPN()

    def tearDown(self):
        """ Clear the env so we don't impact other tests """
        try:
            os.unlink(self.testing_conffile)
        except OSError:  # pragma: no cover
            # ... else, there was nothing there (likely) ...
            if os.path.exists(self.testing_conffile):
                # ... but if there is, we couldn't delete it, so complain.
                raise

    def test_03_ingest_no_config_files(self):
        """ With no config files, get an exception """
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS', new=[]):
            with self.assertRaises(IOError):
                self.library._ingest_config_from_file()

    def test_04_ingest_no_config_file(self):
        """ With all missing config files, get an exception """
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['/tmp/no-such-file.txt']):
            with self.assertRaises(IOError):
                self.library._ingest_config_from_file()

    def test_05_ingest_bad_config_file(self):
        """ With a bad config file, get an exception """
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['test/context.py']):
            with self.assertRaises(IOError):
                self.library._ingest_config_from_file()

    def test_06_ingest_config_from_file(self):
        """ With an actual config file, get a populated ConfigParser """
        test_reading_file = '/tmp/test-reader.txt'
        with open(test_reading_file, 'w') as filepointer:
            filepointer.write('[aa]\nbb = cc\n')
        filepointer.close()
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=['/tmp/no-such-file.txt', test_reading_file]):
            result = self.library._ingest_config_from_file()
        os.remove(test_reading_file)
        self.assertIsInstance(result, configparser.ConfigParser,
                              'Did not create a config object')
        self.assertEqual(result.sections(), ['aa'],
                         'Should have found one configfile section.')
        self.assertEqual(result.options('aa'), ['bb'],
                         'Should have found one option.')
        self.assertEqual(result.get('aa', 'bb'), 'cc',
                         'Should have read a correct value.')

    def test_10_logging(self):
        """ Validate that log does the right things. """
        self.library.log_to_stdout = True
        with mock.patch('mozdef_client_config.ConfigedMozDefEvent') as mock_logger:
            instance = mock_logger.return_value
            with mock.patch.object(instance, 'send') as mock_send, \
                    mock.patch.object(instance, 'syslog_convert', return_value='msg1'), \
                    mock.patch('sys.stdout', new=StringIO()) as fake_out:
                self.library.log('blah1', severity='CRITICAL', details='foo1')
        self.assertEqual(instance.category, 'authentication')
        self.assertEqual(instance.source, 'openvpn')
        self.assertIn('vpn', instance.tags)
        self.assertEqual(instance.summary, 'blah1')
        self.assertEqual(instance.details, 'foo1')
        mock_send.assert_called_once_with()
        self.assertIn('msg1', fake_out.getvalue())

        self.library.log_to_stdout = False
        with mock.patch('mozdef_client_config.ConfigedMozDefEvent') as mock_logger:
            instance = mock_logger.return_value
            with mock.patch.object(instance, 'send') as mock_send, \
                    mock.patch.object(instance, 'syslog_convert', return_value='msg1'), \
                    mock.patch('sys.stdout', new=StringIO()) as fake_out:
                self.library.log('blah1', severity='CRITICAL')
        mock_send.assert_called_once_with()
        self.assertEqual('', fake_out.getvalue())

    def test_20_auth_bogus_user(self):
        """ A bogus user is denied """
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch.object(OpenVPNCredentials, 'load_variables_from_environment',
                                   side_effect=ValueError), \
                    mock.patch('sys.stderr', new=StringIO()) as fake_out:
                res = self.library.main_authentication()
        self.assertFalse(res, 'invalid environment must be denied access')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')
        self.assertIn('Traceback', fake_out.getvalue())

    def test_21_auth_bad_iam(self):
        """ A user is denied when IAM is unreachable """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary', side_effect=RuntimeError):
                res = self.library.main_authentication()
        self.assertFalse(res, 'Disconnected IAM must be denied access')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_22_auth_disabled_user(self):
        """ A disabled user is denied """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam:
                iam_instance = mock_iam.return_value
                with mock.patch.object(iam_instance, 'user_allowed_to_vpn', return_value=False):
                    res = self.library.main_authentication()
        self.assertFalse(res, 'Disallowed user must be denied access')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_23_auth_1fa_garbage_pw(self):
        """ 1fa user with a 2fa / bonkers 'password' """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'push'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                    mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                      return_value=True):
                with mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                       return_value=False):
                    res = self.library.main_authentication()
        self.assertFalse(res, '1fa user with stupid colliding passwords must be denied access')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_24_auth_1fa_bad_pw(self):
        """ 1fa user with a bad password """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'hunter2'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                    mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                      return_value=True):
                with mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                       return_value=False), \
                        mock.patch.object(mock_iam.return_value, 'non_mfa_vpn_authentication',
                                          return_value=False):
                    res = self.library.main_authentication()
        self.assertFalse(res, '1fa user with a wrong password must be denied access')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_25_auth_1fa_good_pw(self):
        """ 1fa user with a good password """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'hunter2'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                    mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                      return_value=True):
                with mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                       return_value=False), \
                        mock.patch.object(mock_iam.return_value, 'non_mfa_vpn_authentication',
                                          return_value=True):
                    res = self.library.main_authentication()
        self.assertTrue(res, '1fa user with the right password can get in')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'true')

    def test_26_auth_2fa_no_load(self):
        """ 2fa user who we can't load into Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'hunter2'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                    mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                      return_value=True), \
                    mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                      return_value=True):
                with mock.patch('duo_auth.DuoAPIAuth'), \
                        mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=False):
                    res = self.library.main_authentication()
        self.assertFalse(res, '2fa user is denied when we cannot load up our Duo search')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_27_auth_2fa_fail_to_auth(self):
        """ 2fa user who we can't load into Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'hunter2'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                    mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                      return_value=True), \
                    mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                      return_value=True):
                with mock.patch('duo_auth.DuoAPIAuth'), \
                        mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                        mock.patch.object(DuoAPIAuth, 'main_auth', side_effect=IOError), \
                        mock.patch('sys.stderr', new=StringIO()) as fake_out:
                    res = self.library.main_authentication()
        self.assertFalse(res, '2fa user is denied when Duo errors out on us')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')
        self.assertIn('Traceback', fake_out.getvalue())

    def test_27_auth_2fa_duo_deny(self):
        """ 2fa user who is denied by Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'hunter2'
        with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                  return_value=True), \
                mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                  return_value=True):
            with mock.patch('duo_auth.DuoAPIAuth'), \
                    mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                    mock.patch.object(DuoAPIAuth, 'main_auth', return_value=False):
                res = self.library.main_authentication()
        self.assertFalse(res, '2fa user is denied when Duo denies them')

    def test_27_auth_2fa_duo_allow(self):
        """ 2fa user who is allowed by Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['password'] = 'hunter2'
        with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                  return_value=True), \
                mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                  return_value=True):
            with mock.patch('duo_auth.DuoAPIAuth'), \
                    mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                    mock.patch.object(DuoAPIAuth, 'main_auth', return_value=True):
                res = self.library.main_authentication()
        self.assertTrue(res, '2fa user is allowed when Duo allows them')
