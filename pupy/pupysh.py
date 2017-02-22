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
import pupylib.PupyServer
import pupylib.PupyCmd
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

__author__='Nicolas VERDIER'
__version__='v1.3'
__date__='Jun 17 2016'

def print_version():
    print("Pupy - %s"%(__version__))

if __name__=="__main__":
    parser = argparse.ArgumentParser(prog='pupysh', description="Pupy console")
    parser.add_argument('--log-lvl', '--lvl', help="change log verbosity", dest="loglevel", choices=["DEBUG","INFO","WARNING","ERROR"], default="WARNING")
    parser.add_argument('--version', help="print version and exit", action='store_true')
    parser.add_argument('-t', '--transport', choices=[x for x in network.conf.transports.iterkeys()], help="change the transport ! :-)")
    parser.add_argument('--ta', '--transport-args', dest='transport_args', help="... --transport-args 'OPTION1=value OPTION2=val ...' ...")
    parser.add_argument('--port', '-p', help="change the listening port", type=int)
    parser.add_argument('--workdir', help='Set Workdir (Default = current workdir)')
    args=parser.parse_args()

    if args.workdir:
       os.chdir(args.workdir)

    if args.version:
        print_version()
        exit(0)
    loglevel=logging.WARNING
    if args.loglevel=="ERROR":
        loglevel=logging.ERROR
    elif args.loglevel=="DEBUG":
        loglevel=logging.DEBUG
    elif args.loglevel=="INFO":
        loglevel=logging.INFO
    else:
        loglevel=logging.WARNING
    logging.basicConfig(format='%(asctime)-15s - %(levelname)-5s - %(message)s')
    logging.getLogger().setLevel(loglevel)

    pupyServer=pupylib.PupyServer.PupyServer(args.transport, args.transport_args, port=args.port)
    try:
        import __builtin__ as builtins
    except ImportError:
        import builtins
    builtins.glob_pupyServer=pupyServer # dirty ninja trick for this particular case avoiding to touch rpyc source code
    pcmd=pupylib.PupyCmd.PupyCmd(pupyServer)
    pupyServer.start()
    while True:
        try:
            pcmd.cmdloop()
        except Exception as e:
            print(traceback.format_exc())
            time.sleep(0.1) #to avoid flood in case of exceptions in loop
            pcmd.intro=''
