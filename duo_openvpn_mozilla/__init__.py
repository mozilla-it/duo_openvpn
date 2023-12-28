"""
    This library is for integrating openvpn and Duo, to perform MFA
    verification of incoming users.

    This library bridges the openvpn credential-gathering library
    and the Duo authentication library, sending credentials between
    the two.

    It also uses the iamvpnlibrary to learn about users, and logs
    the results to syslog.
"""
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com
import sys
import os
import traceback
import datetime
import socket
import json
import syslog
import configparser
import iamvpnlibrary
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
sys.dont_write_bytecode = True


class DuoTimeoutError(Exception):
    ''' Just an exception to indicate we timed out talking to Duo '''

class DuoOpenVPN(object):
    """
        This is mainly implemented as a class because it's an easier way to
        keep track of our config-file based configuration.  For the most part
        this class acts as a 'main' block for information coordination.
    """
    CONFIG_FILE_LOCATIONS = ['duo_openvpn.conf',
                             '/usr/local/etc/duo_openvpn.conf',
                             '/etc/openvpn/duo_openvpn.conf',
                             '/etc/duo_openvpn.conf']

    def __init__(self):
        """
            Build a dictionary of our config options into this object.
        """
        self.configfile = self._ingest_config_from_file()
        duo_client_args = {}
        for key, val in self.configfile.items('duo-credentials'):
            duo_client_args[key] = val
        self.duo_client_args = duo_client_args
        try:
            self.failopen = self.configfile.getboolean('duo-behavior',
                                                       'fail_open')
        except (configparser.NoOptionError, configparser.NoSectionError):
            # Fail secure if they can't tell us otherwise.
            self.failopen = False

        try:
            self.duo_timeout = self.configfile.getint('duo-behavior',
                                                      'duo-timeout')
            if self.duo_timeout < 0 or self.duo_timeout >= 3600:
                # A Duo transaction should take seconds.  If you're trying
                # to wait more than an hour, just accept no timeout, or
                # write me and give me a reason that this is wrong.
                self.duo_timeout = 300
        except (configparser.NoOptionError, configparser.NoSectionError):
            # Fail secure if they can't tell us otherwise.
            self.duo_timeout = 300

        try:
            self.event_send = self.configfile.getboolean(
                'duo-openvpn', 'syslog-events-send')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.event_send = False

        try:
            _base_facility = self.configfile.get(
                'duo-openvpn', 'syslog-events-facility')
        except (configparser.NoOptionError, configparser.NoSectionError):
            _base_facility = 'auth'
        try:
            self.event_facility = getattr(syslog, 'LOG_{}'.format(_base_facility.upper()))
        except (AttributeError):
            self.event_facility = syslog.LOG_AUTH

    def _ingest_config_from_file(self):
        """
            pull in config variables from a system file
        """
        config = configparser.ConfigParser()
        for filename in self.__class__.CONFIG_FILE_LOCATIONS:
            if os.path.isfile(filename):
                try:
                    config.read(filename)
                    break
                except (configparser.Error):
                    pass
        else:
            # We deliberately fail out here rather than try to
            # exit gracefully, because we are severely misconfig'ed.
            raise IOError('Config file not found')
        return config

    def log(self, summary, details, severity):
        """
            This segment sends a log to syslog
        """
        if not self.event_send:
            return
        output_json = {
            'category': 'authentication',
            'processid': os.getpid(),
            'severity': severity,
            'processname': sys.argv[0],
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'details': details,
            'hostname': socket.getfqdn(),
            'summary': summary,
            'tags': ['vpn', 'duosecurity'],
            'source': 'openvpn',
        }
        syslog_message = json.dumps(output_json)
        syslog.openlog(facility=self.event_facility)
        syslog.syslog(syslog_message)

    def _get_user_data_from_environment(self):
        """
            Internal function for reading in environmental variables
            returns a loaded OpenVPNCredentials object, or None
        """
        # Set up a user object based on the environmental variables.
        user_data = OpenVPNCredentials()
        try:
            user_data.load_variables_from_environment()
        except ValueError:
            # This happens when we have a total mismatch, like, openvpn
            # didn't send valid environmental variables to the plugin,
            # or someone got here without a certificate(!?!)
            self.log(summary='FAIL: VPN environmental load, software bug',
                     severity='ERROR',
                     details={'error': 'true',
                              'success': 'false', },)
            traceback.print_exc()
            return None
        return user_data

    def local_authentication(self):
        """
            The main authentication function.
            Return True if the user successfully authenticated.
            Return False if they didn't.
            It's expected that we'll handle errors within this and not raise.
        """
        # Set up a user object based on the environmental variables.
        user_data = self._get_user_data_from_environment()
        if not isinstance(user_data, OpenVPNCredentials):
            return False

        username = user_data.username
        client_ipaddr = user_data.client_ipaddr
        password = user_data.password
        session_state = user_data.session_state

        try:
            iam_searcher = iamvpnlibrary.IAMVPNLibrary()
        except RuntimeError:
            # Couldn't connect to the IAM service:
            self.log(summary=('FAIL: Unable to connect to IAM'),
                     severity='INFO',
                     details={'username': username,
                              'sourceipaddress': client_ipaddr,
                              'success': 'false', },)
            return False

        if not iam_searcher.user_allowed_to_vpn(username):
            # Here we have a user not allowed to VPN in at all.
            # This is some form of "their account is disabled" and/or
            # they aren't in the approved ACL list.
            self.log(summary=('FAIL: VPN user "{}" denied for not being '
                              'allowed to use the VPN'.format(username)),
                     severity='INFO',
                     details={'username': username,
                              'sourceipaddress': client_ipaddr,
                              'success': 'false', },)
            return False

        if not iam_searcher.does_user_require_vpn_mfa(username):
            # We've hit a special snowflake user who does not require MFA.
            if password is None:
                # If a password of 'None' makes it through, auth will fail.
                # 'None' can happen if someone tries using a Duo keyword as a
                # password.  In the unbelievably small chance that password
                # is correct, it's an unacceptably bad password.  Punt them.
                # I mean, really, you've got a non-MFA user, who then has no
                # password / a horrible one.  That's zero factors.
                allow_1fa = False
            else:
                allow_1fa = iam_searcher.non_mfa_vpn_authentication(username,
                                                                    password)

            if allow_1fa:
                summary = 'SUCCESS: non-MFA user "{}" accepted by password'
            else:
                summary = 'FAIL: non-MFA user "{}" denied by password'

            self.log(summary=summary.format(username),
                     severity='INFO',
                     details={'username': username,
                              'sourceipaddress': client_ipaddr,
                              'success': str(allow_1fa).lower(), },)
            return allow_1fa

        # If we are sent a session_state, it is because --auth-gen-token is
        # running as 'external-auth'.  We need to reason out what to do based
        # on the value we are sent.
        if session_state is None:
            # No variable was sent: we're not in external-auth mode.  We're not authoritative.
            pass
        elif session_state in ['Initial', 'Expired', 'Invalid', 'AuthenticatedEmptyUser', 'ExpiredEmptyUser']:
            # We are in a state where we haven't been approved by the server.  Ask Duo.
            pass
        elif session_state in ['Authenticated']:
            # We are in a state where the server says we're okay.  This means we have enough
            # information to validate, so we don't need to talk to Duo.  On our own authority,
            # approve the connection.
            return True

        # We've hit the point of indecision (and that's okay!)  We don't know enough to either
        # allow or deny the connection.  We return None as a tristate to indicate "keep going."
        return None

    def remote_authentication(self):
        '''
            See if the remote server likes us
        '''
        # Set up a user object based on the environmental variables.
        user_data = self._get_user_data_from_environment()
        if not isinstance(user_data, OpenVPNCredentials):
            return False

        username = user_data.username
        client_ipaddr = user_data.client_ipaddr

        # We don't establish a Duo object until we need it.
        duo = DuoAPIAuth(fail_open=self.failopen,
                         log_func=self.log,
                         **self.duo_client_args)

        if not duo.load_user_to_verify(user_config=user_data):
            # The load_user_to_verify method is benign, so we should
            # never fail to load, but if we do it'll be hard to find,
            # so this 'if' block captures an edge case we've never seen,
            # just in case.
            self.log(summary='FAIL: VPN user failed MFA pre-load',
                     severity='INFO',
                     details={'username': username,
                              'sourceipaddress': client_ipaddr,
                              'success': 'false', },)
            return False

        try:
            return duo.main_auth()
        except DuoTimeoutError:
            self.log(summary='FAIL: Duo timed out',
                     severity='INFO',
                     details={'username': username,
                              'error': 'true',
                              'sourceipaddress': client_ipaddr,
                              'success': 'false', },)
            return False
        except Exception:  # pylint: disable=broad-except
            # Deliberately catch all errors until we can find what can
            # go wrong.
            self.log(summary='FAIL: VPN User auth failed, software bug',
                     severity='ERROR',
                     details={'username': username,
                              'error': 'true',
                              'sourceipaddress': client_ipaddr,
                              'success': 'false', },)
            traceback.print_exc()
            return False

    def main_authentication(self):
        '''
            Perform reasonable authentication balance between local and remote auth methods
        '''
        local_auth = self.local_authentication()
        if isinstance(local_auth, bool):
            # Local deemed itself authoritative, return its answer.
            return local_auth
        if local_auth is None:
            # Local was nonauthoritatively okay, so check remote.
            remote_auth = self.remote_authentication()
            if isinstance(remote_auth, bool):
                # Remote deemed itself authoritative, return its answer.
                return remote_auth
        return False
