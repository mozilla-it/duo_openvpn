#!/usr/bin/env python
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributors:
# Guillaume Destuynder <gdestuynder@mozilla.com>
#
# Note: parsing and matching are a little dirty, but so is the OpenVPN management protocol. So yeah :)
# This works as of OpenVPN 2.3.4. It should work in later versions too, hopefully - unless/until syntax changes.
#
# Recommended openvpn server settings:
# management /var/run/openvpn-udp-stage.socket unix
# management-client-group vpnmgmt

import socket
import mozlibldap
import imp
import mozdef_client as mozdef
import select
import sys

cfg_path = ['duo_openvpn.conf', '/etc/openvpn/duo_openvpn.conf', '/etc/duo_openvpn.conf']
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
    print("Failed to load config")
    sys.exit(1)

# MozDef Logging
mdmsg = mozdef.MozDefMsg(config.MOZDEF_URL, tags=['openvpn', 'killusers'])
if config.USE_SYSLOG:
    mdmsg.sendToSyslog = True
if not config.USE_MOZDEF:
    mdmsg.syslogOnly = True


class vpnmgmt():
    def __init__(self, socket_path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connect(socket_path)
        self.sock.setblocking(0)

    def connect(self, p):
        self.sock.connect(p)
        # get rid of the welcome msg
        self.sock.recv(1024)

    def send(self, command, stopon=None):
        # keep on reading until hitting timeout, in case the server is being slow
        # stopon is used to make this faster, you don't need to wait for timeout
        # if you know you already have the data. Be careful that it doesn't match
        # unwanted data, though.
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

    def getpid(self):
        return self.send('pid', stopon='\r\n').split('\r')[0]

    def getstatus(self):
        data = self.send('status', stopon='ROUTING TABLE').split('\r\n')
        read_start = False
        users = {}
        for line in data:
            if line.startswith('Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since'):
                read_start = True
                continue
            if line.startswith('ROUTING TABLE') or line == '':
                break
            if read_start:
                u = line.split(',')
                users[u[0]] = u[1:]
        return users

    def kill(self, user):
        ret = self.send('kill '+user, stopon='\r\n')
        return (self.success(ret), ret)


def usage():
    print("USAGE: "+sys.argv[0]+" </var/run/openvpn.sock>")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    vpn = vpnmgmt(sys.argv[1])
    l = mozlibldap.MozLDAP(config.LDAP_URL, config.LDAP_BIND_DN, config.LDAP_BIND_PASSWD)
    # this splits the LDAP DN format thus should theoretically never fail (the token
    # for split is the LDAP token). It extracts the mail= part of the DN so that we
    # have the same email as the OpenVPN certificate CN email/login name for matching.
    enabled_users = [x.split(',')[0].split('=')[1] for x in l.get_all_enabled_users()]
    vpn_status = vpn.getstatus()
    vpn_users = [x for x in vpn_status]

    for user in vpn_users:
        if user not in enabled_users:
            mdmsg.send(summary=user+': not in the list of active LDAP users - disconnecting',
                       details={'srcip': vpn_status[user][0].split(':')[0],
                                'user': user,
                                'connected_since': vpn_status[user][2]})
            vpn.kill(user)