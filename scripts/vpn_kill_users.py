#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributors:
# Guillaume Destuynder <gdestuynder@mozilla.com>
# Greg Cox <gcox@mozilla.com>
#
# Note: parsing and matching are a little dirty,
#       but so is the OpenVPN management protocol.
# This works as of OpenVPN 2.4.6.
#
# Recommended openvpn server settings:
# management /var/run/openvpn-udp-stage.socket unix
# management-client-group vpnmgmt

import socket
import imp
import mozdef_client as mozdef
import select
import sys
import ldap
import re

MINIMUM_LDAP_ACTIVE_USER_SIZE = 100
# If you get fewer than ^ allowed-users, bail out:
# Do not try to disconnect any users.

# FIXME: clean up positional args in format after we leave 2.6 behind

cfg_path = ['duo_openvpn.conf',
            '/etc/openvpn/duo_openvpn.conf',
            '/etc/duo_openvpn.conf']
config = None

for cfg in cfg_path:
    try:
        config = imp.load_source('config', cfg)
    except:
        pass
    else:
        # use first config file found
        break

if config is None:
    print('Failed to load config')
    sys.exit(1)

# MozDef Logging
mdmsg = mozdef.MozDefMsg(config.MOZDEF_URL, tags=['openvpn', 'killusers'])
if config.USE_SYSLOG:
    mdmsg.sendToSyslog = True
if not config.USE_MOZDEF:
    mdmsg.syslogOnly = True


class ldap_searcher(object):
    LDAP_BASE = 'dc=mozilla'
    LDAP_GROUPS_BASE = 'ou=groups,'+LDAP_BASE
    VPN_GROUP = 'cn=vpn_default'
    # ^ this can be None if you like

    def __init__(self, url, bind_dn, bind_passwd=None):
        """ set up the object.  Use class vars from above to set up. """
        if bind_passwd is not None:
            self.conn = ldap.initialize(url)
            self.conn.start_tls_s()
            self.conn.simple_bind_s(bind_dn, bind_passwd)
        else:
            raise Exception('You need to authenticate via password')
        self.base = self.LDAP_BASE
        self.groups_base = self.LDAP_GROUPS_BASE
        self.vpn_group = self.VPN_GROUP

    def _get_all_enabled_users(self):
        """
        desc: search for all non-disabled users and return theie DNs.
        return: set(['mail=user@foo.com,o=com,dc=company',
                    'mail=user2@foo.com,o=com,dc=company' ...])
        """
        res = self.conn.search_s(self.base, ldap.SCOPE_SUBTREE,
                                 '(&(!(employeeType=DISABLED))(mail=*))',
                                 ['dn'])
        return set(x[0] for x in res)

    def _get_acl_allowed_users(self):
        """
        desc: search for all user DNs that belong to the
              group we have specified as the default VPN ACL

        return: set(['mail=user@foo.com,o=com,dc=company',
                     'mail=user2@foo.com,o=com,dc=company' ...])
        """
        members = set()
        ures = self.conn.search_s(self.groups_base, ldap.SCOPE_SUBTREE,
                                  '('+self.vpn_group+')', ['member'])
        for dn, attr in ures:
            for user in attr['member']:
                members.add(user)
        return members

    def get_allowed_users(self):
        """
        An allowed user is someone:
            whose account is enabled via ldap AND
            who is in the acl for minimum LDAP privs.
        Pull either, and they should be off VPN.
        return: set(['mail=user@foo.com,o=com,dc=company',
                     'mail=user2@foo.com,o=com,dc=company' ...])
        """
        ldap_enabled_users = self._get_all_enabled_users()
        if self.vpn_group is not None:
            vpn_acl_enabled_users = self._get_acl_allowed_users()
            allowed_users = ldap_enabled_users & vpn_acl_enabled_users
        else:
            allowed_users = ldap_enabled_users
        return allowed_users

    def get_user_email(self, dn):
        """
        desc: get a user's emails from their ldap object
        return: [str] ex: ["user@foo.com"]
               (there can be more than one, first entry is the default)
        """
        res = self.conn.search_s(dn, ldap.SCOPE_BASE,
                                 '(objectClass=*)', ['mail'])
        return res[0][1]['mail']


class vpnmgmt():
    """class vpnmgmt creates a socket to the openvpn management server"""
    def __init__(self, socket_path):
        try:
            self.sock = socket.socket(socket.AF_UNIX,
                                      socket.SOCK_STREAM)
            self._connect(socket_path)
            self.sock.setblocking(0)
        except Exception, e:
            print('VPN setup failed: %s' % e)
            sys.exit(3)

    def _connect(self, p):
        self.sock.connect(p)
        # get rid of the welcome msg
        self.sock.recv(1024)

    def _send(self, command, stopon=None):
        # keep on reading until hitting timeout, in case the server is
        # being slow.  stopon is used to make this faster: you don't
        # need to wait for timeout if you know you already have the data.
        # Be careful that stopon doesn't match the data, though.
        self.sock.send(command+'\r\n')
        data = ''
        while True:
            r, w, e = select.select([0, self.sock], [], [], 1)
            buf = ''
            for fd in r:
                if fd == self.sock:
                    buf = self.sock.recv(1024)
                    data += buf
            if buf == '' or stopon is not None and data.find(stopon) != -1:
                break
        return data

    def success(self, msg):
        # checks if OpenVPN returned SUCCESS or ERROR or else.
        if msg.startswith('SUCCESS'):
            return True
        elif msg.startswith('INFO'):
            return True
        else:
            return False

    def _getstatus(self):
        """interact with the server and try to get out the status"""
        try:
            data = self._send('status', 'END')
            return data

        except Exception, e:
            print('Unable to get status: %s' % e)
            sys.exit(1)

    def getusers(self):
        data = self._getstatus()
        users = {}
        if (re.findall('^TITLE', data)):
            # version 2 or 3, the first thing is a TITLE header;
            # We don't need multiline here.
            tab1 = re.findall('^CLIENT_LIST[,\t](.+)[,\t](\d+\.\d+\.\d+\.\d+\:\d+)[,\t]', data, re.MULTILINE)
            # These DO need multiline, since data is a stream and we're
            # 'abusing' ^ by anchoring to newlines in the middle
        else:
            # version 1
            tab1 = re.findall(',(.+),(\d+\.\d+\.\d+\.\d+\:\d+)', data)
        for u in tab1:
            # Pass along all the variables in u.
            # This makes "field 1" here be "field 1" later.
            users[u[0]] = u
        return users

    def kill(self, user):
        ret = self._send('kill '+user, stopon='\r\n')
        return (self.success(ret), ret)


def usage():
    print('USAGE: '+sys.argv[0]+' </var/run/openvpn.sock>')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    vpn = vpnmgmt(sys.argv[1])
    l = ldap_searcher(config.LDAP_URL,
                      config.LDAP_BIND_DN,
                      config.LDAP_BIND_PASSWD)

    allowed_users = l.get_allowed_users()

    # If there's a 'too small' set of allowed users (like,
    # from an ldap error), this could mean you could end up
    # with (example) 20 people connected, and 'a couple' of
    # allowed users, and we'd cycle through and disconnect
    # everyone from VPN.  So enforce a minimum, and complain
    # if we're below that.
    #
    # This is a paranoid guess to say "if < some-reasonable-number"
    # and to avoid saying "if no allowed users".  The aim is to
    # cover off the case of "someone enforced an insane search limit",
    # which would pass a "we got SOMETHING back from the server"
    # while still being disastrous for user experience.
    #
    if len(allowed_users) < MINIMUM_LDAP_ACTIVE_USER_SIZE:
        # msg = "LDAP returned fewer than {} users, aborting."
        msg = "LDAP returned fewer than {0} users, aborting."
        print(msg.format(MINIMUM_LDAP_ACTIVE_USER_SIZE))
        sys.exit(1)

    # allowed_users is a list of LDAP DNs at this point.
    # The email for ldap and the OpenVPN certificate CN
    # email/login name should match.
    #
    # This is an expensive loop to get users emails, sorry.
    # This is better than doing a comma-split on the DN.
    #
    allowed_emails = [l.get_user_email(x)[0] for x in allowed_users]
    # allowed_emails is the list of emails allowed to VPN.
    # This SHOULD be also equal to the list of CNs allowed.

    users_connected_to_vpn = vpn.getusers()
    # users_connected_to_vpn is the list of emails on the VPN.

    users_we_plan_to_disconnect = set()
    for user in users_connected_to_vpn:
        # We use 'user not in enabled users' rather than 'user in disabled
        # users' because disabled users would be a higher level ACL,
        # usually reserved for scripts running on the admin nodes.
        # But we checked for minimum-good user sets above.
        if user not in allowed_emails:
            users_we_plan_to_disconnect.add(user)

    # If there's anyone to disconnect, time to kick them now.
    # We fall through and exit silently if not.
    for user in users_we_plan_to_disconnect:
        src_ip = users_connected_to_vpn[user][1].split(':')[0]
        # msg = "{} not in the list of active LDAP users - disconnecting"
        msg = "{0} not in the list of active LDAP users - disconnecting"
        mdmsg.send(summary=msg.format(user),
                   details={'srcip': src_ip,
                            'user': user})
        # print("disconnecting from VPN: {}".format(user))
        print("disconnecting from VPN: {0}".format(user))
        vpn.kill(user)

