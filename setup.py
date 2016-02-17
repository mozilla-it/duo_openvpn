#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2016 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "duo_openvpn",
        py_modules = ['duo_openvpn'],
        version = "1.0.3",
        author = "Guillaume Destuynder",
        author_email = "gdestuynder@mozilla.com",
        description = ("A plugin to OpenVPN to use DuoSecurity and LDAP authentication"),
        license = "MPL",
        keywords = "mozdef duosecurity openvpn",
        url = "https://github.com/mozilla-it/duo_openvpn",
        long_description = read('README.rst'),
        requires = ['mozdef_client'],
        classifiers = [
            "Development Status :: 5 - Production/Stable",
            "Topic :: System :: Logging",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        ],
)
