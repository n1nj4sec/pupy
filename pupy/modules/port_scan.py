# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import logging

__class_name__="PortScan"

@config(cat="network")
class PortScan(PupyModule):
    """ run a TCP port scan """
    dependencies=['portscan', 'scapy']

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="port_scan", description=self.__doc__)
        self.arg_parser.add_argument('--ports','-p', default="21,22,23,80,139,443,445,3389,8000,8080",  help='ports to scan ex: 22,80,443')
        self.arg_parser.add_argument('address', metavar="ip/range", help='IP/range to scan')

    def run(self, args):
        ps=self.client.conn.modules['portscan'].PortScanner()
        ports=[int(x) for x in args.ports.split(',')]
        res=ps.scan(args.address, ports)
        self.rawlog(res)
        self.success("Scan finished !")

