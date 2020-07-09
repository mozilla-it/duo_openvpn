# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2018 Mozilla Corporation
""" duo_auth class unit test script """

import unittest
import os
import test.context  # pylint: disable=unused-import
import duo_client
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
from duo_openvpn_mozilla import DuoOpenVPN


class TestDuoAPIAuth(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    """
        These are intended to exercise internal functions of the library's
        DuoOpenVPN class.
    """

    def setUp(self):
        """ Preparing test rig """
        # To get a decent test, we're going to need items from the config
        # file in order to test.
        self.main_object = DuoOpenVPN()
        self.main_object.log_to_stdout = False
        self.normal_user = self.main_object.configfile.get(
            'testing', 'normal_user')
        self.deep_test_rawauth = self.main_object.configfile.getboolean(
            'testing', 'deep_testing_rawauth')
        self.deep_test_mfa = self.main_object.configfile.getboolean(
            'testing', 'deep_testing_mfa')
        self.deep_test_main = self.main_object.configfile.getboolean(
            'testing', 'deep_testing_mainauth')
        #
        os.environ['untrusted_ip'] = 'testing-ip-Unknown-is-OK'
        os.environ['common_name'] = self.normal_user
        user_creds = dict()
        for varname in OpenVPNCredentials.DUO_RESERVED_WORDS:
            os.environ['password'] = varname
            res = OpenVPNCredentials()
            res.load_variables_from_environment()
            user_creds[varname] = res
        self.user_data = user_creds
        #
        self.library = DuoAPIAuth(**self.main_object.duo_client_args)

    def tearDown(self):
        """ Clear the env so we don't impact other tests """
        for varname in ['common_name', 'password', 'username', 'untrusted_ip']:
            if varname in os.environ:
                del os.environ[varname]

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

    def test_preflight_01(self):
        """ preflight fails for bad host """
        self.main_object.duo_client_args['host'] = 'badhost'
        tmplibrary = DuoAPIAuth(**self.main_object.duo_client_args)
        # No user data needs to be loaded to be preflighted
        res = tmplibrary._preflight()
        self.assertFalse(res, '_preflight must be False for a bad host')

    def test_preflight_02(self):
        """ preflight fails for bad skey """
        if not self.deep_test_rawauth:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        self.main_object.duo_client_args['skey'] = 'wrong-passcode'
        tmplibrary = DuoAPIAuth(**self.main_object.duo_client_args)
        # No user data needs to be loaded to be preflighted
        res = tmplibrary._preflight()
        self.assertFalse(res, '_preflight must be False for a bad skey')

    def test_preflight_03(self):
        """ preflight works in general """
        # No user data needs to be loaded to be preflighted
        res = self.library._preflight()
        self.assertTrue(res, '_preflight must be True '
                        'for our standard testing')

    def test_preauth_01(self):
        """ preauth that can't work returns None """
        self.main_object.duo_client_args['host'] = 'badhost'
        tmplibrary = DuoAPIAuth(**self.main_object.duo_client_args)
        tmplibrary.load_user_to_verify(self.user_data['push'])
        res = tmplibrary._preauth()
        self.assertIsNone(res, '_preauth on a damaged server returns None')

    def test_preauth_02(self):
        """ preauth errors on blank users """
        setattr(self.user_data['push'], 'username', '')
        self.library.load_user_to_verify(self.user_data['push'])
        res = self.library._preauth()
        self.assertIsNone(res, '_preauth for a blank user must return None')

    def test_preauth_03(self):
        """ preauth wants to enroll for unknown users """
        setattr(self.user_data['push'], 'username', 'baddie-bad-username')
        self.library.load_user_to_verify(self.user_data['push'])
        res = self.library._preauth()
        self.assertIsInstance(res, dict,
                              '_preauth returns a dict upon success')
        self.assertIn('result', res,
                      '_preauth return must have a "result" key')
        self.assertIn(res['result'], ['deny', 'enroll'],
                      ('_preauth for an unknown user '
                       'must return "deny" or "enroll"'))

    def test_preauth_04(self):
        """ preauth wants to auth standard user """
        self.library.load_user_to_verify(self.user_data['push'])
        res = self.library._preauth()
        self.assertIsInstance(res, dict,
                              '_preauth returns a dict upon success')
        self.assertIn('result', res,
                      '_preauth return must have a "result" key')
        self.assertEqual(res['result'], 'auth',
                         '_preauth for an known person must return "auth"')

    # We do not preauth-test a user that should only have 1FA.
    # The code should intercept a user and bypass checking before
    # getting to this point.  If you're into preauth, you've lost.

    def test_auth_00(self):
        """ _auth with garbage factor fails """
        setattr(self.user_data['auto'], 'factor', 'junk')
        self.library.load_user_to_verify(self.user_data['auto'])
        res = self.library._auth()
        self.assertIsNone(res, '_auth with junk factor must return None')

    def test_mfa_00(self):
        """ _do_mfa_for_user with garbage factor fails """
        setattr(self.user_data['auto'], 'factor', 'junk')
        self.library.load_user_to_verify(self.user_data['auto'])
        res = self.library._do_mfa_for_user()
        self.assertFalse(res, '_do_mfa_for_user with junk factor '
                         'must return False')

    def test_auth_02(self):
        """ _auth with sms fails """
        self.library.load_user_to_verify(self.user_data['sms'])
        # We test this even with an incapable device.  It should just fail.
        res = self.library._auth()
        self.assertIsNone(res, '_auth with "sms" factor must return None')

    def test_mfa_02(self):
        """ _do_mfa_for_user with sms fails """
        self.library.load_user_to_verify(self.user_data['sms'])
        # We test this even with an incapable device.  It should just fail.
        res = self.library._do_mfa_for_user()
        self.assertFalse(res, '_do_mfa_for_user with "sms" factor '
                         'must return False')

    def _can_we_run_a_test(self, testcase):
        res = self.library._preauth()
        for device in res['devices']:
            if 'capabilities' in device:
                if testcase in device['capabilities']:
                    return True
        return False

    def _auth_testing_run(self, testcase, answer):
        if not self.deep_test_rawauth:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        self.library.load_user_to_verify(self.user_data[testcase])
        if testcase != 'passcode' and not self._can_we_run_a_test(testcase):
            return self.skipTest('incapable device for {tc}'.format(
                tc=testcase))
        res = self.library._auth()
        self.assertIsInstance(res, dict,
                              '_auth must return a dict')
        self.assertIn('result', res,
                      '_auth return must have a "result" key')
        self.assertIn(res['result'], ['allow', 'deny'],
                      '_auth result must be "allow" or "deny"')
        self.assertEqual(res['result'], answer,
                         '_auth result must be "{ans}"'.format(ans=answer))

    def _mfa_testing_run(self, testcase, answer):
        if not self.deep_test_mfa:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        self.library.load_user_to_verify(self.user_data[testcase])
        if testcase != 'passcode' and not self._can_we_run_a_test(testcase):
            return self.skipTest('incapable device for {tc}'.format(
                tc=testcase))
        res = self.library._do_mfa_for_user()
        self.assertIsInstance(res, bool,
                              '_do_mfa_for_user must return a bool')
        self.assertEqual(res, answer,
                         '_do_mfa_for_user result must '
                         'be "{ans}"'.format(ans=answer))

    def test_auth_03(self):
        """ _auth with auto - PLEASE ALLOW """
        return self._auth_testing_run('auto', 'allow')

    def test_mfa_03(self):
        """ _do_mfa_for_user with auto - PLEASE ALLOW """
        return self._mfa_testing_run('auto', True)

    def test_auth_04(self):
        """ _auth with phone - PLEASE ALLOW """
        return self._auth_testing_run('phone', 'allow')

    def test_mfa_04(self):
        """ _do_mfa_for_user with phone - PLEASE ALLOW """
        return self._mfa_testing_run('phone', True)

    def test_auth_05(self):
        """ _auth with push - PLEASE ALLOW """
        return self._auth_testing_run('push', 'allow')

    def test_mfa_05(self):
        """ _do_mfa_for_user with push - PLEASE ALLOW """
        return self._mfa_testing_run('push', True)

    def test_auth_06(self):
        """ _auth with VALID PASSCODE """
        if not self.deep_test_rawauth:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        passcode = raw_input('enter a valid passcode: ')
        os.environ['password'] = passcode
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.user_data['passcode'] = creds
        return self._auth_testing_run('passcode', 'allow')

    def test_mfa_06(self):
        """ _auth with VALID PASSCODE """
        if not self.deep_test_mfa:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        passcode = raw_input('enter a valid passcode: ')
        os.environ['password'] = passcode
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.user_data['passcode'] = creds
        return self._mfa_testing_run('passcode', True)

    def test_auth_13(self):
        """ _auth with auto - PLEASE DENY """
        return self._auth_testing_run('auto', 'deny')

    def test_mfa_13(self):
        """ _do_mfa_for_user with auto - PLEASE DENY """
        return self._mfa_testing_run('auto', False)

    def test_auth_14(self):
        """ _auth with phone - PLEASE DENY """
        return self._auth_testing_run('phone', 'deny')

    def test_mfa_14(self):
        """ _do_mfa_for_user with phone - PLEASE DENY """
        return self._mfa_testing_run('phone', False)

    def test_auth_15(self):
        """ _auth with push - PLEASE DENY """
        return self._auth_testing_run('push', 'deny')

    def test_mfa_15(self):
        """ _do_mfa_for_user with push - PLEASE DENY """
        return self._mfa_testing_run('push', False)

    def test_auth_16(self):
        """ _auth with INVALID PASSCODE """
        # We are going to play the 1-in-a-million odds here and save
        # a click.  Change up the lines if you hate this.
        # if not self.deep_test_rawauth:
        #     return self.skipTest('because of .deep_testing preference')
        # passcode = raw_input('enter an invalid passcode: ')
        passcode = '000000'
        os.environ['password'] = passcode
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.user_data['passcode'] = creds
        return self._auth_testing_run('passcode', 'deny')

    def test_mfa_16(self):
        """ _do_mfa_for_user with INVALID PASSCODE """
        # We are going to play the 1-in-a-million odds here and save
        # a click.  Change up the lines if you hate this.
        # if not self.deep_test_mfa:
        #     return self.skipTest('because of .deep_testing preference')
        # passcode = raw_input('enter an invalid passcode: ')
        passcode = '000000'
        os.environ['password'] = passcode
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.user_data['passcode'] = creds
        return self._mfa_testing_run('passcode', False)

    # A word on testing main_auth.
    # main_auth has exceptions in it, for handling the cases of a server
    # failing open, and bad runtime responses coming out of it.  We're
    # not doing a full test in here, because the sheer number of options
    # we'd have to test would be INSANE.  The subtests will have to handle
    # some of this, and trust that you'll eyeball the function for "if
    # we're broken at runtime, that 'if' statement near the top will save us.
    # As such, we are mostly testing the return fields coming out of
    # _auth, and that we're getting the right answers.  For the most part,
    # all of these checks will look uncannily similar to the _auth and
    # _mfa checks above.

    def test_main_00(self):
        """ main_auth with garbage factor fails """
        setattr(self.user_data['auto'], 'factor', 'junk')
        self.library.load_user_to_verify(self.user_data['auto'])
        res = self.library.main_auth()
        self.assertFalse(res, 'main_auth with junk factor '
                         'must return False')

    def test_main_01(self):
        """ main_auth with no connection goes fail_open """
        self.main_object.duo_client_args['host'] = 'badhost'
        for state in (True, False):
            tmplibrary = DuoAPIAuth(fail_open=state,
                                    **self.main_object.duo_client_args)
            tmplibrary.load_user_to_verify(self.user_data['auto'])
            res = tmplibrary.main_auth()
            self.assertEqual(res, state,
                             'main_auth with no connection must return '
                             'the fail_open state')

    def test_main_02(self):
        """ main_auth with sms fails """
        self.library.load_user_to_verify(self.user_data['sms'])
        # We test this even with an incapable device.  It should just fail.
        res = self.library.main_auth()
        self.assertFalse(res, 'main_auth with "sms" factor '
                         'must return False')

    def _main_testing_run(self, testcase, answer):
        if not self.deep_test_main:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        self.library.load_user_to_verify(self.user_data[testcase])
        if testcase != 'passcode' and not self._can_we_run_a_test(testcase):
            return self.skipTest('incapable device for {tc}'.format(
                tc=testcase))
        res = self.library.main_auth()
        self.assertIsInstance(res, bool,
                              'main_auth must return a bool')
        self.assertEqual(res, answer,
                         'main_auth result must '
                         'be "{ans}"'.format(ans=answer))

    def test_main_03(self):
        """ main_auth with auto - PLEASE ALLOW """
        return self._main_testing_run('auto', True)

    def test_main_04(self):
        """ main_auth with phone - PLEASE ALLOW """
        return self._main_testing_run('phone', True)

    def test_main_05(self):
        """ main_auth with push - PLEASE ALLOW """
        return self._main_testing_run('push', True)

    def test_main_06(self):
        """ _auth with VALID PASSCODE """
        if not self.deep_test_main:  # pragma: no cover
            return self.skipTest('because of .deep_testing preference')
        passcode = raw_input('enter a valid passcode: ')
        os.environ['password'] = passcode
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.user_data['passcode'] = creds
        return self._main_testing_run('passcode', True)

    def test_main_13(self):
        """ main_auth with auto - PLEASE DENY """
        return self._main_testing_run('auto', False)

    def test_main_14(self):
        """ main_auth with phone - PLEASE DENY """
        return self._main_testing_run('phone', False)

    def test_main_15(self):
        """ main_auth with push - PLEASE DENY """
        return self._main_testing_run('push', False)

    def test_main_16(self):
        """ main_auth with INVALID PASSCODE """
        # We are going to play the 1-in-a-million odds here and save
        # a click.  Change up the lines if you hate this.
        # if not self.deep_test_main:
        #     return self.skipTest('because of .deep_testing preference')
        # passcode = raw_input('enter an invalid passcode: ')
        passcode = '000000'
        os.environ['password'] = passcode
        creds = OpenVPNCredentials()
        creds.load_variables_from_environment()
        self.user_data['passcode'] = creds
        return self._main_testing_run('passcode', False)

    def test_log_good(self):
        """ Test sending a log message to mozdef - all good """
        # There is no raise or return.  We're just poking at
        # the function and making sure it doesn't raise.
        tmplibrary = DuoAPIAuth(log_func=self.main_object.log,
                                **self.main_object.duo_client_args)
        tmplibrary.log(summary='TEST message',
                       severity='DEBUG',)
