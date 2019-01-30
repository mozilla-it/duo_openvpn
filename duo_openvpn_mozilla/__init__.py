"""
    This library is for integrating openvpn and Duo, to perform MFA
    verification of incoming users.

    This library bridges the openvpn credential-gathering library
    and the Duo authentication library, sending credentials between
    the two.

    It also uses the iamvpnlibrary to learn about users, and logs
    the results to mozdef.
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
import mozdef_client_config
from duo_openvpn_mozilla.duo_auth import DuoAPIAuth
from duo_openvpn_mozilla.openvpn_credentials import OpenVPNCredentials
sys.dont_write_bytecode = True
try:
    # 2.7's module:
    from ConfigParser import SafeConfigParser as ConfigParser
except ImportError:
    # 3's module:
    from configparser import ConfigParser


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
        if (self.configfile.has_section('duo-behavior') and
                self.configfile.has_option('duo-behavior', 'fail_open')):
            self.failopen = self.configfile.getboolean('duo-behavior',
                                                       'fail_open')
        else:
            # Fail secure if they can't tell us otherwise.
            self.failopen = False
        # We use mozdef to log about activities.  However, for triage,
        # it is in our interest to keep records, real-time, on the server.
        # mozdef can do syslog, but that is a separate file from the vpn's
        # activity log.  So, to put it all in one place, we can log to
        # stdout.
        if (self.configfile.has_section('duo-behavior') and
                self.configfile.has_option('duo-behavior', 'log_to_stdout')):
            self.log_to_stdout = self.configfile.getboolean('duo-behavior',
                                                            'log_to_stdout')
        else:
            self.log_to_stdout = True

    def _ingest_config_from_file(self, conf_file=None):
        """
            pull in config variables from a system file
        """
        if conf_file is None:
            conf_file = self.__class__.CONFIG_FILE_LOCATIONS
        if isinstance(conf_file, basestring):
            conf_file = [conf_file]
        config = ConfigParser()
        for filename in conf_file:
            if os.path.isfile(filename):
                try:
                    config.read(filename)
                    break
                except:  # pylint: disable=bare-except
                    # This bare-except is due to 2.7
                    # limitations in configparser.
                    pass
        else:
            raise IOError('Config file not found')
        return config

    def log(self, summary, severity=None, details=None):
        """
            This segment sends a log to mozdef for important events.
        """
        logger = mozdef_client_config.ConfigedMozDefEvent()
        logger.category = 'Authentication'
        logger.source = 'openvpn'
        logger.tags = ['vpn', 'duosecurity']
        logger.summary = summary
        if severity is None:
            severity = 'INFO'
        logger.set_severity_from_string(severity)
        if details is not None:
            logger.details = details
        logger.send()
        # Print to stdout here because we want a local copy of the results.
        # We could log to syslog, but that separates our files from the
        # openvpn log to syslog.
        if self.log_to_stdout:
            print logger.syslog_convert()

    def main_authentication(self):  # pylint: disable=too-many-return-statements
        """
            The main authentication function.
            Return True if the user successfully authenticated.
            Return False if they didn't.
            It's expected that we'll handle errors within this and not raise.
        """
        # Set up a user object based on the environmental variables.
        user_data = OpenVPNCredentials()
        user_data.load_variables_from_environment()
        if not user_data.is_valid():
            return False

        username = user_data.username
        client_ipaddr = user_data.client_ipaddr
        password = user_data.password

        iam_searcher = iamvpnlibrary.IAMVPNLibrary()
        if not iam_searcher.user_allowed_to_vpn(username):
            # Here we have a user not allowed to VPN in at all.
            # This is some form of "their account is disabled" and/or
            # they aren't in the approved ACL list.
            self.log(summary=('FAIL: VPN user "{}" administratively '
                              'denied'.format(username)),
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

        duo.load_user_to_verify(user_config=user_data)

        try:
            return duo.main_auth()
        except:  # pylint: disable=bare-except
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

        # We should never get here.
        self.log(summary='FAIL: VPN User fell through all possible '
                         'Duo checks, software bug',
                 severity='ERROR',
                 details={'username': username,
                          'error': 'true',
                          'success': 'false', },)
        return False
