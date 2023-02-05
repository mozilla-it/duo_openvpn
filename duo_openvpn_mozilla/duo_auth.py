"""
    This library is for performing a multifactor authentication with Duo.
    There's the possibility of name confusion, sorry.

    This library is specifically an implementation against duo's python
    client, https://github.com/duosecurity/duo_client_python, and ignores
    their openvpn client, https://github.com/duosecurity/duo_openvpn
    which seems to have gone unmaintained.

    The larger package is about full integration with openvpn in a fashion
    that lines up with our business.  This library is simply focused on
    getting an answer back from Duo and saying yes/no, this person has
    authenticated and should be allowed in.
"""
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com
import sys
import socket
import six
import six.moves.http_client
import duo_client
sys.dont_write_bytecode = True


class DuoAPIAuth(duo_client.Auth):
    """
        This class interfaces with the Duo service and verifies MFA access
        when a user needs to have it.

        This is more or less a recreation on top of duo_client
        with some extra logging for us.
    """
    def __init__(self, *args, **kwargs):
        """
            Hidden in args/kwargs is that we accept all the features that
            would be passed along to duo_client.Auth for init.
        """
        self.hostname = socket.gethostname()
        self._fail_open = kwargs.pop('fail_open', False)
        self.log_func = kwargs.pop('log_func', None)
        self.user_config = None

        super(DuoAPIAuth, self).__init__(*args, **kwargs)

    def load_user_to_verify(self, user_config):
        """
            Take in the information about the user we should be
            evaluating.
        """
        # We are not going to fully evaluate the user config here.
        # All we're doing is verifying that this object looks 'close.'
        # Full evaluation is another function's job.
        try:
            if not isinstance(user_config.username, six.string_types):
                return False
            if not isinstance(user_config.factor, six.string_types):
                # Something with a None for a factor is not going to be
                # able to MFA.
                return False
        except AttributeError:
            return False
        self.user_config = user_config
        return True

    def log(self, *args, **kwargs):
        """
            This logs if there's a logging function we were passed in at
            initialization.  Otherwise we drop it on the floor.
        """
        if self.log_func is not None:
            self.log_func(*args, **kwargs)

    def _preflight(self):
        """
            Verify that we have a sane interactivity mechanism with Duo.
        """
        try:
            # See if we can reach the server.
            # https://duo.com/docs/authapi#/ping
            # This either works or explodes, and all it returns is a
            # server timestamp.  So we don't care about the return values.
            self.ping()  # parent-call
        except socket.error as err:
            self.log(summary='FAIL: DuoAPIAuth ping {}'.format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return False

        try:
            # See if we have valid keys to use on the server.
            # https://duo.com/docs/authapi#/check
            self.check()  # parent-call
        except socket.error as err:
            # Super unlikely.  Ping should've hit this.
            self.log(summary='FAIL: DuoAPIAuth check socket {}'.format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return False
        except RuntimeError as err:
            # This is when the call returns a 401:
            self.log(summary='FAIL: DuoAPIAuth check runtime {}'.format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return False

        return True

    def _preauth(self):
        """
            Test whether a user is authorized to log in, and if so, how.
            Return the 'result' field from the API, which is a string
            listing the next steps in authentication.
            Return None if we hit a failure case talking to Duo.
            Will raise out if you haven't hit load_user_to_verify before.
        """
        try:
            # https://duo.com/docs/authapi#/preauth
            res = self.preauth(username=self.user_config.username,
                               ipaddr=self.user_config.client_ipaddr)
            # parent-call
        except socket.error as err:
            # Super unlikely.  Ping should've hit this.
            self.log(summary=('FAIL: DuoAPIAuth preauth '
                              'socket-failed {}').format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return None
        except RuntimeError as err:
            # This is when the call returns a 400 for bad parameters.
            self.log(summary=('FAIL: DuoAPIAuth preauth '
                              'runtime-failed {}').format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return None
        except six.moves.http_client.BadStatusLine as err:
            # This is when the call horks midway
            # We shouldn't need this once
            #   https://github.com/duosecurity/duo_client_python/issues/111
            # is handled
            self.log(summary=('FAIL: DuoAPIAuth preauth '
                              'had a failure talking to Duo. {}').format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return None
        return res

    def _auth(self):
        """
            This is effectively a wrapper/interpreter for the Duo
            'auth' method.  Here we call an auth (to perform an auth
            for a user we have predetermined NEEDS an auth).  We
            return the resulting auth call's return value, or None
            if there was something whereby we would never let someone in,
            such as a socket error, a failed API call, or a factor
            like 'sms' which does not provide a path to authentication.
        """
        # The mandatory args are here.  We add more later depending
        # on which factor we're using.
        passing_args = dict(
            username=self.user_config.username,
            factor=self.user_config.factor,
            ipaddr=self.user_config.client_ipaddr,)
        if self.user_config.factor == 'passcode':
            # Passcode authing must pass the passcode.  Duh.
            passing_args.update(
                passcode=self.user_config.passcode)
        elif self.user_config.factor == 'auto':
            # This code path exists only for completeness.  The only way
            # you get here is if someone puts in the password as 'auto',
            # which we don't advertise.  But, in any case, do what they ask,
            # since it's not dissimilar from what we do otherwise.
            passing_args.update(device='auto')
        elif self.user_config.factor == 'push':
            # We default device to 'auto' because that tells Duo to
            # "Use the out-of-band factor (push or phone) recommended by Duo
            # as the best for the user's devices."  And since we can't tell
            # from the VPN which device to use from multiple, 'auto' is our
            # best/only bet.  The other parameters are just using some of
            # the niceties that the push form offers us.
            # -- https://duo.com/docs/authapi#/auth
            passing_args.update(
                device='auto',
                type='OpenVPN login',
                pushinfo="From%20server="+self.hostname, )
        elif self.user_config.factor == 'sms':
            # sms is not an auth mechanism, but is a way to get new codes.
            # This is not our job, so we don't help people out on this.
            self.log(summary=('FAIL: User "{}" denied for trying '
                              'sms auth'.format(self.user_config.username)),
                     severity='INFO',
                     details={
                         'username': self.user_config.username,
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return None
        elif self.user_config.factor == 'phone':
            # This code path exists only for completeness.  The only way
            # you get here is if someone puts in the password as 'phone',
            # which we don't advertise.  But, in any case, do what they ask,
            # since it's not dissimilar from what we do otherwise.
            passing_args.update(device='auto')
        else:
            # Something we've never heard of.  You only get here if we have
            # a code error.
            self.log(summary='FAIL: _auth unworkable factor, software bug',
                     severity='ERROR',
                     details={
                         'username': self.user_config.username,
                         'error': 'true',
                         'duofactor': self.user_config.factor,
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return None

        try:
            # https://duo.com/docs/authapi#/auth
            res = self.auth(**passing_args)  # parent-call
        except socket.error as err:
            # Super unlikely.  Ping should've hit this.
            self.log(summary='FAIL: DuoAPIAuth auth '
                             'socket-failed {}'.format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return None
        except RuntimeError as err:
            # This is when the call returns a 400.for bad parameters.
            # This is hard to simulate, as we pre-massage the parameters
            # that go into an auth call, so any failure here is hard to test.
            self.log(summary='FAIL: DuoAPIAuth auth '
                             'runtime-failed {}'.format(err),
                     details={'error': 'true',
                              'success': 'false', },
                     severity='CRITICAL')
            return None
        return res

    def _do_mfa_for_user(self):
        """
            This function is where we focus on one user who needs to Duo.
            We have stripped away a lot of edge cases and verified
            connectivity to the service, so we process the return from
            the auth function.

            Return True if the user may connect.
            Return Frue if the user may not connect.
            You must make a choice, and should not raise.
        """
        res = self._auth()
        if res is None:
            # A None coming back at us, we can do nothing with.
            # Trust that auth did some logging for us and quit here.
            return False
        if not isinstance(res, dict) or ('result' not in res):
            # This should never happen.  This is a supreme failure
            # in code testing.
            self.log(summary='FAIL: User auth failed, software bug',
                     severity='ERROR',
                     details={
                         'username': self.user_config.username,
                         'error': 'true',
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return False
        if res['result'] == 'allow':
            _summary = ('SUCCESS: User "{user}" authenticated by DuoAPIAuth'
                        '').format(user=self.user_config.username)
            self.log(summary=_summary,
                     severity='INFO',
                     details={
                         'username': self.user_config.username,
                         'duofactor': self.user_config.factor,
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'true', },)
            return True
        _summary = ('FAIL: User "{user}" denied by DuoAPIAuth: '
                    '{msg}').format(user=self.user_config.username,
                                    msg=res['status_msg'])
        self.log(summary=_summary,
                 severity='WARNING',
                 details={
                     'username': self.user_config.username,
                     'duofactor': self.user_config.factor,
                     'sourceipaddress': self.user_config.client_ipaddr,
                     'success': 'false', },)
        return False

    def main_auth(self):
        # pylint: disable=too-many-return-statements
        """
            This function does all the work, and is the only intended
            public function.  Given all the setup of the call (user
            environment + config file) use the Duo client to determine
            if the user is allowed to connect or not.

            Return True if the user may connect.
            Return Frue if the user may not connect.
            You must make a choice, and should not raise.
        """
        if not self._preflight():
            # Failed preflight - there's no connection to Duo.
            # Fail safe / fail secure.
            if self._fail_open:
                self.log(summary=('SUCCESS: Duo failed open, '
                                  'user "{}" allowed '
                                  'in'.format(self.user_config.username)),
                         severity='CRITICAL',
                         details={
                             'username': self.user_config.username,
                             'error': 'false',
                             'sourceipaddress': self.user_config.client_ipaddr,
                             'success': 'true',
                         })
            return self._fail_open

        preauth = self._preauth()

        if preauth is None:
            # A failure at this point means something failed in _preauth.
            # We explicitly need to fail here.  If it's because we lost
            # the connection, it's okay.  On the next connection, fail_open
            # will do the right thing.  But that's the super-unlikely case.
            # the likely case is that there was a parameter issue, and that
            # means we didn't get an approval, so kick the user out because
            # something is bad.
            self.log(summary=('FAIL: User "{}" denied due to preauth failure'
                              ''.format(self.user_config.username)),
                     severity='ERROR',
                     details={
                         'username': self.user_config.username,
                         'error': 'true',
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return False
        if not isinstance(preauth, dict) or ('result' not in preauth):
            self.log(summary='FAIL: User got a non-dict preauth '
                             'reply, software bug',
                     severity='ERROR',
                     details={
                         'username': self.user_config.username,
                         'error': 'true',
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return False
        if preauth['result'] == 'allow':
            # This is a somewhat unexpected case, as it is someonw who
            # would check in with Duo, yet be allowed in without doing
            # a MFA proof.  We must return True since they're approved,
            # but it's an unusual case to come across.
            self.log(summary=('SUCCESS: User "{}" allowed without MFA'
                              ''.format(self.user_config.username)),
                     severity='INFO',
                     details={
                         'username': self.user_config.username,
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'true', },)
            return True
        if preauth['result'] == 'enroll':
            # We do not have a user that needs enrolling, to test against.
            # The key here is, this must return False to indicate a failed
            # login attempt.
            # It's not our job to enroll, so kick them out.
            self.log(summary=('FAIL: Unexpected/non-enrolled Duo '
                              'user "{}" denied'
                              ''.format(self.user_config.username)),
                     severity='INFO',
                     details={
                         'username': self.user_config.username,
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return False
        if preauth['result'] == 'deny':
            # We do not have a perpetually-locked-out user to test against.
            # The key here is, this must return False to indicate a failed
            # login attempt.
            self.log(summary=('FAIL: User "{}" explicitly denied by Duo'
                              ''.format(self.user_config.username)),
                     severity='INFO',
                     details={
                         'username': self.user_config.username,
                         'sourceipaddress': self.user_config.client_ipaddr,
                         'success': 'false', },)
            return False
        if preauth['result'] == 'auth':
            # An MFA user.  Time to go to work.
            # This is the main use case of this 'if' cascade, and the only
            # one we are likely to ever encounter.
            #
            #self.log(summary=('User "{}" being authenticated by Duo'
            #                  ''.format(self.user_config.username)),
            #         severity='INFO',
            #         details={
            #             'username': self.user_config.username,
            #             'sourceipaddress': self.user_config.client_ipaddr},)
            # Skip logging here, as the subfunction has the answers
            # and will log when it gets answers
            return self._do_mfa_for_user()
        # The reply from Duo is unknown.  Probably an API changed.
        _summary = ('FAIL: Unexpected result from DuoAPIAuth: '
                    '{msg}').format(msg=preauth['result'])
        self.log(summary=_summary,
                 severity='ERROR',
                 details={
                     'username': self.user_config.username,
                     'error': 'true',
                     'sourceipaddress': self.user_config.client_ipaddr,
                     'success': 'false', },)
        return False
