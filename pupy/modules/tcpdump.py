# -*- coding: utf-8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, PcapWriter
from threading import Event

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser
)

__class_name__ = "TcpdumpModule"


@config(cat="network", tags=["sniff", "pcap"])
class TcpdumpModule(PupyModule):
    """ module to reproduce some of the classic tcpdump tool functions """

    dependencies = (
        'scapy',
        'tcpdump'
    )

    terminate = None
    wait = Event()

    @classmethod
    def init_argparse(cls):
        example = 'Example:\n'
        example += '>> tcpdump -i eth0 --bpf tcp.port==80 -s\n'

        cls.arg_parser = PupyArgumentParser(prog='tcpdump.py', description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument("-s", "--save-pcap", action="store_true", help="save to a pcap file")
        cls.arg_parser.add_argument("--count", type=int, default=0, help="sniff at max n packets")
        cls.arg_parser.add_argument("-i", "--iface", default=None, help="change default iface")
        cls.arg_parser.add_argument("--timeout", type=int, default=None, help="stop the capture after timeout seconds")
        # yup mandatory cause you have to put pupy's IP/PORT anyway
        cls.arg_parser.add_argument("--bpf", required=True, help="use a BPF (Warning: It is highly advised to whitelist"
                                                                 " pupy's shell IP/PORT you are currently using to "
                                                                 "avoid a nasty Larsen effect)")
        # cls.arg_parser.add_argument("command", choices=["start", "stop"])

    def printer(self, pcap_writer=None, print_summary=True):
        def pkt_callback(pkt):
            try:
                pkt = Ether(pkt)
            except Exception as e:
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

        filepath = None

        if self.client.is_windows():
            from modules.lib.windows.winpcap import init_winpcap
            init_winpcap(self.client)

        pktwriter = None

        if args.save_pcap:
            config = self.client.pupsrv.config
            filepath = config.get_file('pcaps', {'%c': self.client.short_name()})
            pktwriter = PcapWriter(filepath, append=True, sync=True)

        tcpdump = self.client.remote('tcpdump', 'run', False)

        self.wait.clear()

        try:
            name, self.terminate = tcpdump(
                self.printer(pcap_writer=pktwriter),
                self.on_error,
                args.iface,
                args.bpf,
                args.timeout,
                count=args.count)

            self.success(u'Scapy tcpdump on "{}" - started'.format(name))
            self.wait.wait()
            self.success(u'Scapy tcpdump on "{}" - completed'.format(name))

            if filepath:
                self.info('Pcap stored to: {}'.format(filepath))

        except Exception as e:
            self.wait.set()
            self.error('Error: ' + ' '.join(x for x in e.args if type(x) in (str, unicode)))

    def interrupt(self):
        if self.terminate:
            self.terminate()

        self.wait.set()
