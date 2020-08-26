# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2020 Mozilla Corporation
""" openvpn integration script """

import unittest
import os
import sys
import test.context  # pylint: disable=unused-import
import mock
import duo_openvpn
from duo_openvpn_mozilla import DuoOpenVPN  # pylint: disable=unused-import
if sys.version_info.major >= 3:
    from io import StringIO  # pragma: no cover
else:
    from io import BytesIO as StringIO  # pragma: no cover


class TestOpenVPNScript(unittest.TestCase):
    """
        Coverage test for the openvpn script that starts all this.
    """
    def test_01_no_control_file(self):
        """ When there's no auth_control_file, we must die. """
        with mock.patch('sys.stdout', new=StringIO()) as fake_out, \
                self.assertRaises(SystemExit) as exiting:
            duo_openvpn.main()
        self.assertEqual(exiting.exception.code, 1)
        self.assertEqual('No auth_control_file env variable provided.\n', fake_out.getvalue())

    def test_05_write_failed(self):
        """ When we can't write out auth_control_file, we must die """
        os.environ['auth_control_file'] = '/tmp/foo'
        with mock.patch('duo_openvpn.DuoOpenVPN'), \
                self.assertRaises(SystemExit) as exiting, \
                mock.patch('duo_openvpn.open', create=True, side_effect=IOError):
            duo_openvpn.main()
        self.assertEqual(exiting.exception.code, 1)

    def test_10_access_denied(self):
        """ When auth is refused, don't let someone in. """
        os.environ['auth_control_file'] = '/tmp/foo'
        with mock.patch('duo_openvpn.DuoOpenVPN') as mock_duo, \
                self.assertRaises(SystemExit) as exiting, \
                mock.patch('duo_openvpn.open', create=True,
                           return_value=mock.MagicMock(spec=StringIO())) as mock_open, \
                mock.patch.object(mock_duo.return_value, 'main_authentication', return_value=False):
            duo_openvpn.main()
        file_handle = mock_open.return_value.__enter__.return_value
        file_handle.write.assert_called_with('0')
        self.assertEqual(exiting.exception.code, 0)

    def test_11_access_granted(self):
        """ When auth is allowed, let someone in. """
        os.environ['auth_control_file'] = '/tmp/foo'
        with mock.patch('duo_openvpn.DuoOpenVPN') as mock_duo, \
                self.assertRaises(SystemExit) as exiting, \
                mock.patch('duo_openvpn.open', create=True,
                           return_value=mock.MagicMock(spec=StringIO())) as mock_open, \
                mock.patch.object(mock_duo.return_value, 'main_authentication', return_value=True):
            duo_openvpn.main()
        file_handle = mock_open.return_value.__enter__.return_value
        file_handle.write.assert_called_with('1')
        self.assertEqual(exiting.exception.code, 0)
