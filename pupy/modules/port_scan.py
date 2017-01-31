# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from modules.lib.windows.winpcap import init_winpcap
import logging
from datetime import datetime
from netaddr import *

__class_name__="PortScan"

@config(cat="network")
class PortScan(PupyModule):
    """ run a TCP port scan """
    dependencies=['portscan', 'scapy']
    max_clients=1

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="port_scan", description=self.__doc__)
        self.arg_parser.add_argument('--ports','-p', default="21,22,23,80,139,443,445,1433,1521,3389,7001,8000,8080",  help='ports to scan ex: 22,80,443')
        self.arg_parser.add_argument('--timeout', default=4,  help='timeout (default: %(default)s)')
        self.arg_parser.add_argument('--threads', default=10,  help='number of threads (default: %(default)s)')
        self.arg_parser.add_argument('target', metavar="ip/range", help='IP/range')

    def run(self, args):
        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target)

        ports = [int(p.strip()) for p in args.ports.split(',')]
        for host in hosts:
            self.success("Scanning remote host: %s" % host)
            
            t1 = datetime.now()
            open_ports = self.client.conn.modules['portscan'].scan(host, ports, args.threads, args.timeout)
            if open_ports:
                self.log('PORT     STATE')
                for p in open_ports:
                    self.log("%s      open" % p)
            else:
                self.error('No open port found')
            
            # Checking the time again
            t2 = datetime.now()
            total =  t2 - t1
            self.success('Scanning Completed in: %s' % total)