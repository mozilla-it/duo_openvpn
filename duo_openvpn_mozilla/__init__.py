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
import iamvpnlibrary
import datetime
import socket
import json
import syslog
import pytz
from six.moves import configparser
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
sys.dont_write_bytecode = True


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
            # Have to use pytz because py2 is terrible here.
            'timestamp': pytz.timezone('UTC').localize(datetime.datetime.utcnow()).isoformat(),
            'details': details,
            'hostname': socket.getfqdn(),
            'summary': summary,
            'tags': ['vpn', 'duosecurity'],
            'source': 'openvpn',
        }
        syslog_message = json.dumps(output_json)
        syslog.openlog(facility=self.event_facility)
        syslog.syslog(syslog_message)

    def main_authentication(self):  # pylint: disable=too-many-return-statements
        """
            The main authentication function.
            Return True if the user successfully authenticated.
            Return False if they didn't.
            It's expected that we'll handle errors within this and not raise.
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
            return False

        username = user_data.username
        client_ipaddr = user_data.client_ipaddr
        password = user_data.password

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
