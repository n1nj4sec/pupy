# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import sys
import subprocess
import threading
import Queue
import time
import readline
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import datetime
from threading import Event

from pupylib import * # placed after scapy inport to avoid scapy's config collision

__class_name__="TcpdumpModule"

@config(cat="network", tags=["sniff", "pcap"])
class TcpdumpModule(PupyModule):
    """ module to reproduce some of the classic tcpdump tool functions """

    dependencies = ('scapy', 'tcpdump')
    terminate = None
    wait = Event()

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='tcpdump.py', description=cls.__doc__)
        cls.arg_parser.add_argument("-s", "--save-pcap", action="store_true", help="save to a pcap file")
        cls.arg_parser.add_argument("--count", type=int, default=0, help="sniff at max n packets")
        cls.arg_parser.add_argument("-i", "--iface", default=None, help="change default iface")
        cls.arg_parser.add_argument("--timeout", type=int, default=None, help="stop the capture after timeout seconds")
        cls.arg_parser.add_argument("--bpf", required=True, help="use a BPF (Warning: It is highly advised to whitelist pupy's shell IP/PORT you are currently using to avoid a nasty Larsen effect)") #yup mandatory cause you have to put pupy's IP/PORT anyway
        #cls.arg_parser.add_argument("command", choices=["start", "stop"])

    def printer(self, pcap_writer=None, print_summary=True):
        def pkt_callback(pkt):
            try:
                pkt = Ether(pkt)
            except Exception, e:
                self.exception(e)

            if pcap_writer is not None:
                pcap_writer.write(pkt)

            if print_summary:
                self.log(pkt.summary())

        return pkt_callback

    def on_error(self, error=None):
        if error:
            self.error('Scapy error: {}'.format(error))

        self.wait.set()

    def run(self, args):
        self.sniff_sess = None

        if self.client.is_windows():
            from modules.lib.windows.winpcap import init_winpcap
            init_winpcap(self.client)

        pktwriter = None

        if args.timeout==None and args.count==0:
            #TODO patch scapy to have an interruptible sniff() function
            raise PupyModuleError("--timeout or --count options are mandatory for now.")

        if args.save_pcap:
            config = self.client.pupsrv.config or PupyConfig()
            filepath = config.get_file('pcaps', {'%c': self.client.short_name()})
            pktwriter = PcapWriter(filepath, append=True, sync=True)
            self.info('Save pcap to: {}'.format(filepath))

        tcpdump = self.client.remote('tcpdump', 'run', False)

        self.wait.clear()

        name, self.terminate = tcpdump(
            self.printer(pcap_writer=pktwriter),
            self.on_error,
            args.iface,
            args.bpf,
            args.timeout,
            count=args.count
        )

        self.success(u'Scapy tcpdump on "{}" - started'.format(name))
        self.wait.wait()
        self.success(u'Scapy tcpdump on "{}" - completed'.format(name))

    def interrupt(self):
        if self.terminate:
            self.terminate()

        self.wait.set()
