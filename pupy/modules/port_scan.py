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
    terminated = threading.Event()
    max_clients = 1
    connectable = []

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="port_scan", description=self.__doc__)
        self.arg_parser.add_argument('--ports','-p', default="21,22,23,80,139,443,445,1433,1521,3389,7001,8000,8080",  help='ports to scan ex: 22,80,443')
        self.arg_parser.add_argument('--timeout', default=10,  help='timeout (default: %(default)s)')
        self.arg_parser.add_argument('--portion', default=32,  help='number of ports scanned per timeout (default: %(default)s)')
        self.arg_parser.add_argument('target', metavar="ip/range", help='IP/range')

    def run(self, args):
        if "/" in args.target[0]:
            hosts = IPNetwork(args.target[0])
        else:
            hosts = list()
            hosts.append(args.target)

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

        for host in hosts:
            scanner = self.client.conn.modules['network.lib.scan']

            def set_connectable(ports):
                self.connectable = ports
                self.terminated.set()

            self.abort = scanner.scanthread(
                str(host), ports, set_connectable, timeout=args.timeout, portion=args.portion
            )

            self.terminated.wait()

            ports = sorted(self.connectable)

            if ports:
                self.log('{}: {}'.format(host, ', '.join([str(x) for x in ports])))
            else:
                self.log('{}: closed'.format(host))

            if self.abort.is_set():
                break

            self.abort = None

    def interrupt(self):
        if self.abort:
            self.abort.set()

        if self.terminated:
            self.terminated.set()
