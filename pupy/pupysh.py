#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
import sys
if sys.version_info[0]!=2:
    exit("Pupy only support Python 2.x")

import logging
import time
import traceback
import argparse
import os
import os.path
import sys
import network.conf
import getpass

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

if __name__ == '__main__':
    sys.path.insert(0, os.path.join(ROOT, 'client', 'library_patches'))
    sys.path.append(os.path.join(ROOT, 'pupy', 'external', 'scapy'))

try:
    import pupylib.PupySignalHandler
except:
    pass

from pupylib import PupyServer
from pupylib import PupyCmdLoop
from pupylib import PupyCredentials
from pupylib import PupyConfig
from pupylib import __version__

def print_version():
    print("Pupy - %s"%(__version__))

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog='pupysh', description="Pupy console")
    parser.add_argument(
        '--log-level', '-d',
        help='change log verbosity', dest='loglevel',
        choices=['DEBUG','INFO','WARNING','ERROR'],
        default='WARNING')
    parser.add_argument('--version', help='print version and exit', action='store_true')
    parser.add_argument(
        '-l', '--listen',
        help='Bind server listener with transport and args to port.'
        'Example: -l ssl 127.0.0.1:443 -l kcp 80 -l xyz 1234 OPTION1=value OPTION2=value.'
        'Transports: {}'.format(','.join(x for x in network.conf.transports.iterkeys())),
        nargs='+',
        metavar=('TRANSPORT', '<<EXTERNAL_IP=>IP>:<EXTERNAL_PORT=>PORT OPTION=value'),
        action='append', default=[]
    )
    parser.add_argument('--workdir', help='Set Workdir (Default = current workdir)')
    parser.add_argument('-NE', '--not-encrypt', help='Do not encrypt configuration', action='store_true')
    args = parser.parse_args()

    if args.workdir:
       os.chdir(args.workdir)

    if args.version:
        print_version()
        exit(0)

    logging.basicConfig(format='%(asctime)-15s - %(levelname)-5s - %(message)s')
    logging.getLogger().setLevel(args.loglevel)

    PupyCredentials.DEFAULT_ROLE = 'CONTROL'
    if args.not_encrypt:
        PupyCredentials.ENCRYPTOR = None

    # Try to initialize credentials before CMD loop
    try:
        credentials = PupyCredentials.Credentials()
    except PupyCredentials.EncryptionError, e:
        logging.error(e)
        exit(1)

    config = PupyConfig()

    if args.listen:
        listeners = {
            x[0]:x[1:] if len(x) > 1 else [] for x in args.listen
        }

        config.set('pupyd', 'listen', ','.join(listeners.iterkeys()))
        for listener, args in listeners.iteritems():
            if args:
                config.set('listeners', listener, ' '.join(args))

    pupyServer = PupyServer(config, credentials)
    pupycmd = PupyCmdLoop(pupyServer)

    pupyServer.start()
    pupycmd.loop()
    pupyServer.stop()
    pupyServer.finished.wait()
