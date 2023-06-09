#!/usr/bin/env python
"""
    This script handles the direct integration with openvpn's
    auth_control_file / OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY

    See openvpn-plugin.h, openvpn_plugin_func for more.

    Short version: put 1 / 0 in a temp file based on whether
    someone is allowed to connect or not.
"""
# vim: set noexpandtab:ts=4

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Contributors: gdestuynder@mozilla.com
import sys
import os
import signal
from duo_openvpn_mozilla import DuoOpenVPN, DuoTimeoutError
sys.dont_write_bytecode = True

def duo_timeout_handler(signum, frame):
    ''' If we time out, raise an error '''
    raise DuoTimeoutError('Duo timed out')

def main():
    """
        The main function.  Handles file-writing back to openvpn.
        All the good stuff is in class DuoOpenVPN
    """
    #
    # 'auth_control_file' is passed to this script via an
    # environmental variable.  It's an ephemeral file.
    # If we allow a user, put a 1 in the file.
    # If we deny a user, put a 0 in the file.
    #
    control_file_path = os.environ.get('auth_control_file')
    if control_file_path is None:
        # Not having this set is bad: we have no way to tell openvpn
        # what's happened.  Or, you're running the script by hand.
        # Either way, there's no point in continuing.  Get out.
        # We print to STDOUT because this is likely a human, instead
        # of an actual run.  It's possible that we should 'log' this.
        print('No auth_control_file env variable provided.')
        sys.exit(1)
    # There are many more environmental variables needed for this
    # whole process to work.  They are captured/realized farther down in
    # the stack, so, if this looks sad and short, it's intentional.
    # The env-variable work is in OpenVPNCredentials

    auth_object = DuoOpenVPN()
    try:
        if auth_object.duo_timeout:
            signal.signal(signal.SIGALRM, duo_timeout_handler)
            signal.alarm(auth_object.duo_timeout)
        should_allow_in = auth_object.main_authentication()
        if auth_object.duo_timeout:
            signal.alarm(0)
    except DuoTimeoutError:
        should_allow_in = auth_object.failopen
    if should_allow_in:
        writeout_value = str(1)
    else:
        writeout_value = str(0)

    try:
        with open(control_file_path, 'w') as filehandle:
            filehandle.write(writeout_value)
    except IOError:
        # I couldn't write to the file, so we can't tell openvpn what
        # happened.  There's nothing to do but error out.
        sys.exit(1)

    # we wrote out in the try, so we're done.
    sys.exit(0)

if __name__ == "__main__":  # pragma: no cover
    main()
