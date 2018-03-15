# -*- coding: utf-8 -*-

from pupylib.PupyModule import *
from netaddr import IPNetwork, IPAddress
import logging
import random
import threading

__class_name__="PortScan"

@config(cat="network")
class PortScan(PupyModule):
    """ run a TCP port scan """

    abort = None
    connectable = []

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="port_scan", description=cls.__doc__)
        cls.arg_parser.add_argument('--ports','-p', default="21,22,23,80,139,443,445,1433,1521,3389,7001,8000,8080",  help='ports to scan ex: 22,80,443')
        cls.arg_parser.add_argument('--timeout', default=10,  help='timeout (default: %(default)s)')
        cls.arg_parser.add_argument('--portion', default=32,  help='number of ports scanned per timeout (default: %(default)s)')
        cls.arg_parser.add_argument('target', metavar="ip/range", help='IP/range')

    def run(self, args):
        self.terminated = threading.Event()

        scan_range = False

        if '/' in args.target:
            hosts = [ str(x) for x in IPNetwork(args.target) ]
            scan_range = True
            self.log('Scanning range {}: {} hosts'.format(args.target, len(hosts)))
        else:
            hosts = [ args.target ]

        ports = [
            p for prange in args.ports.split(',') for p in (
                xrange(
                    int(prange.split('-')[0]), int(prange.split('-')[1])+1
                ) if '-' in prange else xrange(
                    int(prange), int(prange)+1
                )
            )
        ]

        ports = list(set(ports))
        random.shuffle(ports)

        scanthread = self.client.remote('network.lib.scan', 'scanthread', False)

        def set_connectable(addrs):
            self.connectable = addrs
            self.terminated.set()

        self.connectable = []

        self.abort = scanthread(
            hosts, ports, set_connectable,
            timeout=args.timeout, portion=args.portion
        )

        self.terminated.wait()

        if self.connectable:
            connectable = {}
            for host, port in self.connectable:
                if host in connectable:
                    connectable[host].add(port)
                else:
                    connectable[host] = set([port])

            for host in sorted(connectable.keys()):
                ports = ', '.join([str(port) for port in sorted(list(connectable[host]))])
                self.log('{}: {}'.format(host, ports))

        elif not scan_range:
            self.log('{}: closed'.format(args.target))

        self.abort = None

    def interrupt(self):
        if self.abort:
            self.abort.set()

        if self.terminated:
            self.terminated.set()
