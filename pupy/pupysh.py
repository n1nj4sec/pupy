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

try:
    import pupylib.PupySignalHandler
except:
    pass
import logging
import time
import traceback
import argparse
import os
import os.path
import network.conf

from pupylib import PupyServer
from pupylib import PupyDnsCnc
from pupylib import PupyCmdThread
from pupylib import __version__

from network.lib.igd import IGDClient, UPNPError

def print_version():
    print("Pupy - %s"%(__version__))

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog='pupysh', description="Pupy console")
    parser.add_argument(
        '--log-lvl', '--lvl',
        help='change log verbosity', dest='loglevel',
        choices=['DEBUG','INFO','WARNING','ERROR'],
        default='WARNING')
    parser.add_argument('--version', help='print version and exit', action='store_true')
    parser.add_argument(
        '-t', '--transport',
        choices=[x for x in network.conf.transports.iterkeys()],
        help='change the transport ! :-)')
    parser.add_argument(
        '--ta', '--transport-args', dest='transport_args',
        help='... --transport-args " OPTION1=value OPTION2=val ..." ...')
    parser.add_argument('--port', '-p', help='change the listening port', type=int)
    parser.add_argument('--dns', '-d', help='enable dnscnc server. FDQN:port', type=str)
    parser.add_argument('--external-ip', '-e', help='setup external ip address', type=str)
    parser.add_argument('--workdir', help='Set Workdir (Default = current workdir)')
    args = parser.parse_args()

    if args.workdir:
       os.chdir(args.workdir)

    if args.version:
        print_version()
        exit(0)

    logging.basicConfig(format='%(asctime)-15s - %(levelname)-5s - %(message)s')
    logging.getLogger().setLevel(args.loglevel)

    try:
        igd = IGDClient()
    except UPNPError as e:
        pass

    pupyServer = PupyServer(
        args.transport,
        args.transport_args,
        port=args.port,
        igd=igd,
    )

    pupyDnsCnc = None
    if args.dns:
        if ':' in args.dns:
            fdqn, dnsport = args.dns.split(':')
        else:
            fdqn = args.dns.strip()
            dnsport = 5454

        pupyDnsCnc = PupyDnsCnc(
            fdqn,
            igd=igd,
            port=dnsport,
            connect_host=args.external_ip,
            connect_port=args.port or 443,
            connect_transport=args.transport or 'ssl',
        )

    pupycmd = PupyCmdThread(pupyServer, pupyDnsCnc)

    pupyServer.start()
    pupycmd.start()

    try:
        pupyServer.finished.wait()
    except KeyboardInterrupt:
        pass

    pupycmd.stop()
