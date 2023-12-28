# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" duo_auth class unit test without touching Duo itself """

import unittest
import os
import sys
import datetime
import json
import syslog
import configparser
import test.context  # pylint: disable=unused-import
import mock
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
from duo_openvpn_mozilla import DuoOpenVPN, DuoTimeoutError
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
                               new=[self.testing_conffile]):
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

    def test_07_ingest_defaults(self):
        """ With a weak file, check our defaults """
        self.assertIn('ikey', self.library.duo_client_args)
        self.assertIn('skey', self.library.duo_client_args)
        self.assertIn('host', self.library.duo_client_args)
        self.assertFalse(self.library.failopen)
        self.assertFalse(self.library.event_send)
        self.assertEqual(self.library.event_facility, syslog.LOG_AUTH)
        self.assertEqual(self.library.duo_timeout, 300)

    def test_08_ingest_configs(self):
        """ With a strong file, check our imports """
        config = configparser.ConfigParser()
        config.add_section('duo-credentials')
        config.set('duo-credentials', 'IKEY', 'DI9QQ99X9MK4H99RJ9FF')
        config.set('duo-credentials', 'SKEY', '2md9rw5xeyxt8c648dgkmdrg3zpvnhj5b596mgku')
        config.set('duo-credentials', 'HOST', 'api-9f134ff9.duosekurity.com')
        config.add_section('duo-behavior')
        config.set('duo-behavior', 'fail_open', 'True')
        config.set('duo-behavior', 'duo-timeout', '120')
        config.add_section('duo-openvpn')
        config.set('duo-openvpn', 'syslog-events-send', 'True')
        config.set('duo-openvpn', 'syslog-events-facility', 'local5')
        with open(self.testing_conffile, 'w') as configfile:
            config.write(configfile)
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[self.testing_conffile]):
            self.library = DuoOpenVPN()
        self.assertIn('ikey', self.library.duo_client_args)
        self.assertIn('skey', self.library.duo_client_args)
        self.assertIn('host', self.library.duo_client_args)
        self.assertTrue(self.library.failopen)
        self.assertEqual(self.library.duo_timeout, 120)
        self.assertTrue(self.library.event_send)
        self.assertEqual(self.library.event_facility, syslog.LOG_LOCAL5)

    def test_09_ingest_stupidity(self):
        """ With a terrible file, check our imports """
        config = configparser.ConfigParser()
        config.add_section('duo-credentials')
        config.set('duo-credentials', 'IKEY', 'DI9QQ99X9MK4H99RJ9FF')
        config.set('duo-credentials', 'SKEY', '2md9rw5xeyxt8c648dgkmdrg3zpvnhj5b596mgku')
        config.set('duo-credentials', 'HOST', 'api-9f134ff9.duosekurity.com')
        config.add_section('duo-behavior')
        config.set('duo-behavior', 'duo-timeout', '-5')
        config.add_section('duo-openvpn')
        config.set('duo-openvpn', 'syslog-events-facility', 'junk')
        with open(self.testing_conffile, 'w') as configfile:
            config.write(configfile)
        with mock.patch.object(DuoOpenVPN, 'CONFIG_FILE_LOCATIONS',
                               new=[self.testing_conffile]):
            self.library = DuoOpenVPN()
        self.assertEqual(self.library.duo_timeout, 300)
        self.assertEqual(self.library.event_facility, syslog.LOG_AUTH)

    def test_10_log_nosend(self):
        ''' Test the log method failing to send '''
        self.library.event_send = False
        with mock.patch('syslog.openlog') as mock_openlog, \
                mock.patch('syslog.syslog') as mock_syslog:
            self.library.log('some message', {'foo': 5}, 'CRITICAL')
        mock_openlog.assert_not_called()
        mock_syslog.assert_not_called()

    def test_11_log_send(self):
        ''' Test the log method tries to send '''
        datetime_mock = mock.Mock(wraps=datetime.datetime)
        datetime_mock.now.return_value = datetime.datetime(2020, 12, 25, 13, 14, 15, 123456, tzinfo=datetime.timezone.utc)
        self.library.event_send = True
        self.library.event_facility = syslog.LOG_LOCAL1
        with mock.patch('syslog.openlog') as mock_openlog, \
                mock.patch('syslog.syslog') as mock_syslog, \
                mock.patch('datetime.datetime', new=datetime_mock), \
                mock.patch('os.getpid', return_value=12345), \
                mock.patch('socket.getfqdn', return_value='my.host.name'):
            self.library.log('some message', {'foo': 5}, 'CRITICAL')
        mock_openlog.assert_called_once_with(facility=syslog.LOG_LOCAL1)
        mock_syslog.assert_called_once()
        arg_passed_in = mock_syslog.call_args_list[0][0][0]
        json_sent = json.loads(arg_passed_in)
        details = json_sent['details']
        self.assertEqual(json_sent['category'], 'authentication')
        self.assertEqual(json_sent['processid'], 12345)
        self.assertEqual(json_sent['severity'], 'CRITICAL')
        self.assertIn('processname', json_sent)
        self.assertEqual(json_sent['timestamp'], '2020-12-25T13:14:15.123456+00:00')
        self.assertEqual(json_sent['hostname'], 'my.host.name')
        self.assertEqual(json_sent['summary'], 'some message')
        self.assertEqual(json_sent['source'], 'openvpn')
        self.assertEqual(json_sent['tags'], ['vpn', 'duosecurity'])
        self.assertEqual(details, {'foo': 5})

    def test_20_auth_bogus_user_local(self):
        """ A bogus user is denied """
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch.object(OpenVPNCredentials, 'load_variables_from_environment',
                                   side_effect=ValueError), \
                    mock.patch('sys.stderr', new=StringIO()) as fake_out:
                res = self.library.local_authentication()
        self.assertFalse(res, 'invalid environment must be denied access')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')
        self.assertIn('Traceback', fake_out.getvalue())

    def test_20_auth_bogus_user_remote(self):
        '''
            A bogus user is denied.  This should never actually happen since local will do
            this before us and do the same calls against the same environment, but just in
            case let's test it as a parallel test.
        '''
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch.object(OpenVPNCredentials, 'load_variables_from_environment',
                                   side_effect=ValueError), \
                    mock.patch('sys.stderr', new=StringIO()) as fake_out:
                res = self.library.remote_authentication()
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
                res = self.library.local_authentication()
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
                    res = self.library.local_authentication()
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
                    res = self.library.local_authentication()
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
                    res = self.library.local_authentication()
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
                    res = self.library.local_authentication()
        self.assertTrue(res, '1fa user with the right password can get in')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'true')

    def test_26_auth_local_new_session(self):
        """ 2fa user which needs to talk to Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        #os.environ['session_state'] = None
        with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                  return_value=True):
            with mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                   return_value=True):
                res = self.library.local_authentication()
        self.assertIsNone(res, 'a 2fa user should get None from local_authentication')

    def test_27_auth_local_expired_session(self):
        """ 2fa user passing local authentication """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['session_state'] = 'Expired'
        with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                  return_value=True):
            with mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                   return_value=True):
                res = self.library.local_authentication()
        self.assertIsNone(res, 'a 2fa user with an expired token should continue onward to Duo')

    def test_28_auth_local_returning_session(self):
        """ 2fa user passing local authentication """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        os.environ['session_state'] = 'Authenticated'
        with mock.patch('iamvpnlibrary.IAMVPNLibrary') as mock_iam, \
                mock.patch.object(mock_iam.return_value, 'user_allowed_to_vpn',
                                  return_value=True):
            with mock.patch.object(mock_iam.return_value, 'does_user_require_vpn_mfa',
                                   return_value=True):
                res = self.library.local_authentication()
        self.assertTrue(res, 'a 2fa user with an auth-gen-token should pass local_authentication')

    def test_31_auth_2fa_no_load(self):
        """ 2fa user who we can't load into Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('duo_auth.DuoAPIAuth'), \
                    mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=False):
                res = self.library.remote_authentication()
        self.assertFalse(res, '2fa user is denied when we cannot load up our Duo search')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')

    def test_32_auth_2fa_fail_to_auth(self):
        """ 2fa user who we can't load into Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('duo_auth.DuoAPIAuth'), \
                    mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                    mock.patch.object(DuoAPIAuth, 'main_auth', side_effect=IOError), \
                    mock.patch('sys.stderr', new=StringIO()) as fake_out:
                res = self.library.remote_authentication()
        self.assertFalse(res, '2fa user is denied when Duo errors out on us')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')
        self.assertIn('Traceback', fake_out.getvalue())

    def test_33_auth_2fa_with_duo_offline(self):
        """ 2fa user when we can't talk to Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch.object(DuoOpenVPN, 'log') as mock_log:
            with mock.patch('duo_auth.DuoAPIAuth'), \
                    mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                    mock.patch.object(DuoAPIAuth, 'main_auth', side_effect=DuoTimeoutError), \
                    mock.patch('sys.stderr', new=StringIO()) as fake_out:
                res = self.library.remote_authentication()
        self.assertFalse(res, '2fa user is denied when Duo times out on us')
        # Check the call_args - [1] is the kwargs.
        self.assertEqual(mock_log.call_args[1]['details']['error'], 'true')
        self.assertEqual(mock_log.call_args[1]['details']['success'], 'false')
        self.assertNotIn('Traceback', fake_out.getvalue())

    def test_34_auth_2fa_duo_deny(self):
        """ 2fa user who is denied by Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch('duo_auth.DuoAPIAuth'), \
                mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                mock.patch.object(DuoAPIAuth, 'main_auth', return_value=False):
            res = self.library.remote_authentication()
        self.assertFalse(res, '2fa user is denied when Duo denies them')

    def test_35_auth_2fa_duo_allow(self):
        """ 2fa user who is allowed by Duo """
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = 'bob'
        with mock.patch('duo_auth.DuoAPIAuth'), \
                mock.patch.object(DuoAPIAuth, 'load_user_to_verify', return_value=True), \
                mock.patch.object(DuoAPIAuth, 'main_auth', return_value=True):
            res = self.library.remote_authentication()
        self.assertTrue(res, '2fa user is allowed when Duo allows them')

    def test_41_main_auth_local_knows(self):
        ''' Check answers when local is authoritative '''
        with mock.patch.object(self.library, 'local_authentication', return_value=True):
            res = self.library.main_authentication()
        self.assertTrue(res, 'If local approves, approve everything')
        with mock.patch.object(self.library, 'local_authentication', return_value=False):
            res = self.library.main_authentication()
        self.assertFalse(res, 'If local denies, deny everything')

    def test_42_main_auth_remote_knows(self):
        ''' Check answers when remote is authoritative '''
        with mock.patch.object(self.library, 'local_authentication', return_value=None):
            with mock.patch.object(self.library, 'remote_authentication', return_value=True):
                res = self.library.main_authentication()
            self.assertTrue(res, 'If remote approves, approve everything')
            with mock.patch.object(self.library, 'remote_authentication', return_value=False):
                res = self.library.main_authentication()
            self.assertFalse(res, 'If remote denies, deny everything')

    def test_43_main_auth_someone_fails(self):
        ''' Check answers when someone is confused '''
        with mock.patch.object(self.library, 'local_authentication', return_value='something'):
            res = self.library.main_authentication()
        self.assertFalse(res, 'local_authentication must return a boolean-or-None')
        with mock.patch.object(self.library, 'local_authentication', return_value=None):
            with mock.patch.object(self.library, 'remote_authentication', return_value=None):
                res = self.library.main_authentication()
            self.assertFalse(res, 'remote_authentication must return a boolean')
